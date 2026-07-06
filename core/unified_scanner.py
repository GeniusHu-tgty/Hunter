"""
Hunter Unified Scan Engine — First Principles Design

Core idea: ONE entry point that orchestrates ALL tools.
Recon → Detect → Exploit → Report — fully automated.

Architecture:
1. Recon Phase: probe() → find params/forms/endpoints
2. Detect Phase: auto_sqli + auto_xss + auto_ssti + auto_ssrf + auto_xxe + auto_cmd + auto_idor
3. Exploit Phase: Burp MCP to verify and exploit
4. Report Phase: aggregate findings

Key innovations:
- Tools share state (recon results feed into detection)
- Burp Collaborator integration for blind vulns
- Adaptive testing (fail → try different approach)
- Session management (remember findings across tests)
"""

import time
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ScanContext:
    """Shared state across all tools during a scan."""
    target: str
    session_cookie: str = ""
    csrf_token: str = ""
    forms: List[dict] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    tested_payloads: List[str] = field(default_factory=list)
    collaborator_domain: str = ""
    burp_session: Any = None

    def add_finding(self, vuln_type: str, payload: str, evidence: str, severity: str = "medium"):
        self.findings.append({
            "type": vuln_type,
            "payload": payload,
            "evidence": evidence[:500],
            "severity": severity,
            "timestamp": time.time(),
        })

    def has_finding(self, vuln_type: str) -> bool:
        return any(f["type"] == vuln_type for f in self.findings)

    def get_findings(self, vuln_type: str = "") -> List[dict]:
        if vuln_type:
            return [f for f in self.findings if f["type"] == vuln_type]
        return self.findings


class UnifiedScanner:
    """Unified scan engine that orchestrates all Hunter tools."""

    def __init__(self, target: str, session_cookie: str = "",
                 collaborator_domain: str = ""):
        self.ctx = ScanContext(
            target=target,
            session_cookie=session_cookie,
            collaborator_domain=collaborator_domain,
        )
        self.phases_completed = []
        self.errors = []

    def run_full_scan(self, phases: List[str] = None) -> dict:
        """Run complete scan pipeline.

        Args:
            phases: List of phases to run. Default: all.
                    Options: ['recon', 'sqli', 'xss', 'ssti', 'ssrf', 'xxe', 'cmd', 'idor']
        """
        if phases is None:
            phases = ["recon", "sqli", "xss", "ssti", "ssrf", "xxe", "cmd", "idor"]

        results = {
            "target": self.ctx.target,
            "phases": {},
            "findings": [],
            "summary": {},
        }

        start = time.time()

        for phase in phases:
            try:
                phase_result = self._run_phase(phase)
                results["phases"][phase] = phase_result
                self.phases_completed.append(phase)
            except Exception as e:
                self.errors.append({"phase": phase, "error": str(e)})
                results["phases"][phase] = {"error": str(e)}

        results["findings"] = self.ctx.get_findings()
        results["summary"] = self._generate_summary()
        results["elapsed_ms"] = int((time.time() - start) * 1000)
        results["errors"] = self.errors

        return results

    def _run_phase(self, phase: str) -> dict:
        """Run a single scan phase."""
        if phase == "recon":
            return self._phase_recon()
        elif phase == "sqli":
            return self._phase_sqli()
        elif phase == "xss":
            return self._phase_xss()
        elif phase == "ssti":
            return self._phase_ssti()
        elif phase == "ssrf":
            return self._phase_ssrf()
        elif phase == "xxe":
            return self._phase_xxe()
        elif phase == "cmd":
            return self._phase_cmd()
        elif phase == "idor":
            return self._phase_idor()
        else:
            return {"error": f"Unknown phase: {phase}"}

    def _phase_recon(self) -> dict:
        """Phase 1: Reconnaissance — discover attack surface."""
        import requests
        import re

        # Simple recon: GET the target and extract forms/params/endpoints
        try:
            resp = requests.get(self.ctx.target, timeout=10, verify=False)
            html = resp.text

            # Extract forms
            forms = re.findall(r'<form[^>]*action="([^"]*)"[^>]*method="([^"]*)"', html, re.I)
            self.ctx.forms = [{"action": f[0], "method": f[1]} for f in forms]

            # Extract input parameters
            inputs = re.findall(r'<input[^>]*name="([^"]*)"', html, re.I)
            self.ctx.params = list(set(inputs))

            # Extract endpoints/links
            links = re.findall(r'href="(/[^"]*)"', html)
            self.ctx.endpoints = list(set(links))

            # Extract hidden fields (CSRF tokens etc)
            hidden = re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"', html, re.I)
            for name, value in hidden:
                if 'csrf' in name.lower() or 'token' in name.lower():
                    self.ctx.csrf_token = value

            return {
                "forms_found": len(self.ctx.forms),
                "params_found": len(self.ctx.params),
                "endpoints_found": len(self.ctx.endpoints),
                "csrf_token": self.ctx.csrf_token,
                "params": self.ctx.params[:20],
                "endpoints": self.ctx.endpoints[:20],
            }
        except Exception as e:
            return {"error": str(e)}

    def _phase_sqli(self) -> dict:
        """Phase 2: SQL Injection detection."""
        try:
            from core.auto_sqli import AutoSQLi
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_sqli not available", "suggestion": "pip install requests"}

        results = []

        # Test each parameter discovered in recon
        for param in self.ctx.params:
            sqli = AutoSQLi(
                base_url=self.ctx.target,
                param=param,
                cookie_param="session" if self.ctx.session_cookie else "",
                csrf_url=self.ctx.target + "/login" if self.ctx.csrf_token else "",
            )

            # Quick boolean test first
            bool_result = sqli.test_boolean_blind()
            if bool_result.get("vulnerable"):
                self.ctx.add_finding("sqli", f"' AND 1=1-- on param={param}",
                                     f"Boolean blind: {bool_result}", "high")
                results.append({"param": param, "type": "boolean_blind", "vulnerable": True})
                continue

            # Time-based test
            time_result = sqli.test_time_blind()
            if time_result.get("vulnerable"):
                self.ctx.add_finding("sqli", f"Time-based on param={param}",
                                     f"Time blind: {time_result}", "high")
                results.append({"param": param, "type": "time_blind", "vulnerable": True})
                continue

            # Conditional response test
            cond_result = sqli.test_conditional_response()
            if cond_result.get("vulnerable"):
                self.ctx.add_finding("sqli", f"Conditional response on param={param}",
                                     f"Conditional: {cond_result}", "high")
                results.append({"param": param, "type": "conditional", "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_xss(self) -> dict:
        """Phase 3: XSS detection."""
        try:
            from core.auto_xss import AutoXSS
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_xss not available", "suggestion": "pip install requests"}
        results = []

        for param in self.ctx.params:
            xss = AutoXSS(
                base_url=self.ctx.target,
                param=param,
                csrf_url=self.ctx.target + "/comment" if self.ctx.forms else "",
            )

            # Detect context
            context = xss.detect_context()
            if context == "not_reflected":
                continue

            # Test payloads for detected context
            scan_result = xss.run_full_scan(dom_check=True)
            if scan_result.get("vulnerable"):
                self.ctx.add_finding("xss", scan_result.get("working_payload", ""),
                                     f"Context: {context}, Type: {scan_result.get('xss_type')}", "high")
                results.append({"param": param, "context": context, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_ssti(self) -> dict:
        """Phase 4: SSTI detection."""
        try:
            from core.auto_ssti import AutoSSTI
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_ssti not available", "suggestion": "pip install requests"}
        results = []

        for param in self.ctx.params:
            ssti = AutoSSTI(base_url=self.ctx.target, param=param)
            scan_result = ssti.run_full_scan()

            if scan_result.get("vulnerable"):
                engine = scan_result.get("engine", "unknown")
                self.ctx.add_finding("ssti", scan_result.get("working_payload", ""),
                                     f"Engine: {engine}", "critical")
                results.append({"param": param, "engine": engine, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_ssrf(self) -> dict:
        """Phase 5: SSRF detection."""
        try:
            from core.auto_ssrf import AutoSSRF
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_ssrf not available", "suggestion": "pip install requests"}
        results = []

        for param in self.ctx.params:
            if any(kw in param.lower() for kw in ["url", "uri", "link", "src", "href", "redirect", "path"]):
                ssrf = AutoSSRF(base_url=self.ctx.target, param=param)

                # Test internal access
                internal = ssrf.test_internal_access()
                if internal.get("vulnerable"):
                    self.ctx.add_finding("ssrf", f"Internal access via {param}",
                                         f"Internal: {internal}", "high")
                    results.append({"param": param, "type": "internal_access", "vulnerable": True})

                # Test bypass
                bypass = ssrf.test_bypass()
                if bypass.get("bypasses_found", 0) > 0:
                    self.ctx.add_finding("ssrf", f"Bypass via {param}",
                                         f"Bypass: {bypass}", "high")
                    results.append({"param": param, "type": "bypass", "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_xxe(self) -> dict:
        """Phase 6: XXE detection."""
        try:
            from core.auto_xxe import AutoXXE
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_xxe not available", "suggestion": "pip install requests"}
        results = []

        for param in self.ctx.params:
            xxe = AutoXXE(base_url=self.ctx.target, param=param)
            scan_result = xxe.run_full_scan()

            if scan_result.get("vulnerable"):
                self.ctx.add_finding("xxe", scan_result.get("working_payload", ""),
                                     f"XXE: {scan_result}", "critical")
                results.append({"param": param, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_cmd(self) -> dict:
        """Phase 7: Command Injection detection."""
        try:
            from core.auto_cmd import AutoCMD
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_cmd not available", "suggestion": "pip install requests"}
        results = []

        for param in self.ctx.params:
            if any(kw in param.lower() for kw in ["cmd", "command", "exec", "ping", "ip", "host", "domain"]):
                cmd = AutoCMD(base_url=self.ctx.target, param=param)
                scan_result = cmd.run_full_scan()

                if scan_result.get("vulnerable"):
                    self.ctx.add_finding("cmdi", scan_result.get("working_payload", ""),
                                         f"CMDi: {scan_result}", "critical")
                    results.append({"param": param, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_idor(self) -> dict:
        """Phase 8: IDOR detection."""
        try:
            from core.auto_idor import AutoIDOR
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_idor not available", "suggestion": "pip install requests"}
        results = []

        for endpoint in self.ctx.endpoints:
            if any(kw in endpoint.lower() for kw in ["/api/", "/user/", "/profile/", "/account/"]):
                idor = AutoIDOR(base_url=self.ctx.target, endpoint=endpoint)
                scan_result = idor.run_full_scan()

                if scan_result.get("vulnerable"):
                    self.ctx.add_finding("idor", f"IDOR on {endpoint}",
                                         f"IDOR: {scan_result}", "high")
                    results.append({"endpoint": endpoint, "vulnerable": True})

        return {"endpoints_tested": len(self.ctx.endpoints), "findings": results}

    def _generate_summary(self) -> dict:
        """Generate scan summary."""
        findings = self.ctx.get_findings()
        by_type = {}
        for f in findings:
            t = f["type"]
            if t not in by_type:
                by_type[t] = 0
            by_type[t] += 1

        return {
            "total_findings": len(findings),
            "by_type": by_type,
            "phases_completed": len(self.phases_completed),
            "errors": len(self.errors),
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
        }

    def aggregate_burp_results(self) -> dict:
        """Aggregate results from Burp Scanner, Collaborator, and Proxy.

        This enhances findings with Burp's own analysis:
        - Scanner issues: passive/active scan findings
        - Collaborator: OOB callbacks (blind vulns)
        - Proxy history: interesting patterns in traffic
        """
        # This would integrate with Burp MCP tools
        # For now, return the aggregation structure
        return {
            "scanner_issues": "Use burp(action='scanner_issues') to get",
            "collaborator": "Use burp(action='collaborator_check') to get OOB callbacks",
            "proxy_patterns": "Use burp(action='proxy_search', regex='token|key|password') to find",
        }

    def get_recommendations(self) -> List[str]:
        """Get next-step recommendations based on findings."""
        recs = []

        if not self.ctx.findings:
            recs.append("No vulnerabilities found. Try manual testing or different parameters.")

        if self.ctx.has_finding("sqli"):
            recs.append("SQLi found! Try extracting data: tables → columns → credentials")
            recs.append("Use Burp Collaborator for blind OOB exfiltration")

        if self.ctx.has_finding("xss"):
            recs.append("XSS found! Try stealing cookies or escalating to account takeover")
            recs.append("Use exploit server for DOM/Stored XSS delivery")

        if self.ctx.has_finding("ssrf"):
            recs.append("SSRF found! Try accessing internal services, cloud metadata, or admin panels")
            recs.append("Chain with open redirect if host filter exists")

        if self.ctx.has_finding("ssti"):
            recs.append("SSTI found! Try RCE payload for the identified template engine")

        return recs


def unified_scan_impl(target: str, session_cookie: str = "",
                       collaborator_domain: str = "",
                       phases: List[str] = None) -> dict:
    """MCP entry point for unified scan."""
    scanner = UnifiedScanner(
        target=target,
        session_cookie=session_cookie,
        collaborator_domain=collaborator_domain,
    )
    return scanner.run_full_scan(phases=phases)
