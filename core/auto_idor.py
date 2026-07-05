"""
Hunter v5 — Auto IDOR Engine

Automates Insecure Direct Object Reference detection:
1. Numeric ID manipulation (increment/decrement)
2. UUID/GUID swapping between sessions
3. Response comparison between user contexts
4. Parameter fuzzing for hidden ID fields
"""

import re
import time
import json
from tools.probe import _get_session


class AutoIDOR:
    """Automated IDOR detection engine."""

    def __init__(self, base_url: str, method: str = "GET",
                 session=None, session2=None):
        self.base_url = base_url
        self.method = method.upper()
        self.session = session or _get_session()  # Attacker session
        self.session2 = session2  # Victim session (optional)
        self.vulnerable = False
        self.findings = []

    def _send(self, session, url: str, method: str = None, headers: dict = None) -> dict:
        """Send request with given session."""
        try:
            m = method or self.method
            if m == "GET":
                resp = session.get(url, headers=headers or {}, timeout=10, allow_redirects=False)
            else:
                resp = session.post(url, headers=headers or {}, timeout=10, allow_redirects=False)
            return {
                "status": resp.status_code,
                "body": resp.text[:5000],
                "length": len(resp.text),
                "headers": dict(resp.headers),
            }
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    def test_numeric_id(self, url_template: str, id_range: str = "1-5",
                        current_id: str = "1") -> dict:
        """Test IDOR by manipulating numeric IDs.

        Args:
            url_template: URL with {id} placeholder, e.g. /api/user/{id}
            id_range: Range to test, e.g. "1-5" or "1,2,3,5,10"
            current_id: The user's own ID (baseline)
        """
        results = []

        # Parse range
        if "-" in id_range:
            start, end = id_range.split("-")
            ids = list(range(int(start), int(end) + 1))
        else:
            ids = [int(x.strip()) for x in id_range.split(",")]

        # Get baseline (own data)
        baseline_url = url_template.replace("{id}", str(current_id))
        baseline = self._send(self.session, baseline_url)
        base_len = baseline.get("length", 0)

        for test_id in ids:
            if str(test_id) == str(current_id):
                continue

            test_url = url_template.replace("{id}", str(test_id))
            result = self._send(self.session, test_url)

            if result.get("status") == 200 and result.get("length", 0) > 50:
                # Check if response is different from 404/error
                body = result.get("body", "")
                not_error = not any(x in body.lower()[:200] for x in
                                    ["not found", "404", "forbidden", "403", "unauthorized"])

                if not_error:
                    self.vulnerable = True
                    self.findings.append({
                        "type": "idor_numeric",
                        "severity": "high",
                        "own_id": current_id,
                        "accessed_id": test_id,
                        "url": test_url,
                        "response_length": result["length"],
                    })
                    results.append({
                        "id": test_id, "vulnerable": True,
                        "status": result["status"], "length": result["length"],
                    })
                else:
                    results.append({"id": test_id, "vulnerable": False, "status": result["status"]})
            else:
                results.append({"id": test_id, "vulnerable": False, "status": result.get("status")})

        return {"tested": len(results), "vulnerable": self.vulnerable, "results": results}

    def test_path_manipulation(self, url: str) -> dict:
        """Test IDOR by manipulating URL path segments."""
        results = []

        # Try incrementing/decrementing last numeric segment
        numeric_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        if not numeric_match:
            return {"skipped": True, "reason": "No numeric ID found in URL path"}

        original_id = int(numeric_match.group(1))
        test_ids = [original_id + 1, original_id - 1, original_id + 2, 1, 2, 0]

        for test_id in test_ids:
            test_url = url.replace(str(original_id), str(test_id), 1)
            result = self._send(self.session, test_url)

            if result.get("status") == 200 and result.get("length", 0) > 50:
                body = result.get("body", "").lower()[:200]
                if not any(x in body for x in ["not found", "404", "forbidden", "403"]):
                    self.vulnerable = True
                    self.findings.append({
                        "type": "idor_path",
                        "severity": "high",
                        "original_id": original_id,
                        "accessed_id": test_id,
                        "url": test_url,
                    })
                    results.append({"id": test_id, "vulnerable": True, "url": test_url})
                else:
                    results.append({"id": test_id, "vulnerable": False})
            else:
                results.append({"id": test_id, "vulnerable": False})

        return {"tested": len(results), "results": results}

    def test_parameter_pollution(self, url: str, param: str = "id") -> dict:
        """Test IDOR via parameter pollution."""
        results = []

        pollution_payloads = [
            ("duplicate", f"{param}=1&{param}=2"),
            ("array", f"{param}[]=1"),
            ("json_injection", f'{{"{param}": 1}}'),
        ]

        for name, payload in pollution_payloads:
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{payload}"
            result = self._send(self.session, test_url)

            if result.get("status") == 200 and result.get("length", 0) > 50:
                self.findings.append({
                    "type": "idor_pollution",
                    "severity": "medium",
                    "technique": name,
                    "url": test_url,
                })
                results.append({"technique": name, "vulnerable": True})
            else:
                results.append({"technique": name, "vulnerable": False})

        return {"tested": len(results), "results": results}

    def test_cross_session(self, url: str, victim_cookies: str = "") -> dict:
        """Test IDOR by comparing responses between two sessions."""
        if not victim_cookies and not self.session2:
            return {"skipped": True, "reason": "No second session/cookies provided"}

        # Send with attacker session
        attacker_result = self._send(self.session, url)

        # Send with victim session
        if self.session2:
            victim_result = self._send(self.session2, url)
        else:
            # Use provided cookies
            victim_session = _get_session()
            victim_session.headers["Cookie"] = victim_cookies
            victim_result = self._send(victim_session, url)

        # Compare
        if (attacker_result.get("status") == 200 and
            victim_result.get("status") == 200 and
            attacker_result.get("length", 0) > 50):

            # Check if responses contain similar data structures
            attacker_body = attacker_result.get("body", "")
            victim_body = victim_result.get("body", "")

            if attacker_body != victim_body and abs(len(attacker_body) - len(victim_body)) < 100:
                # Different data but similar structure = likely IDOR
                self.vulnerable = True
                self.findings.append({
                    "type": "idor_cross_session",
                    "severity": "critical",
                    "url": url,
                    "detail": "Different data returned for different sessions",
                })
                return {"vulnerable": True, "attacker_length": len(attacker_body),
                        "victim_length": len(victim_body)}

        return {"vulnerable": False}

    def run_full_scan(self, url: str = "", url_template: str = "",
                      id_range: str = "1-5", current_id: str = "1") -> dict:
        """Run complete IDOR scan."""
        start = time.time()
        results = {"target": url or url_template, "steps": []}

        # Step 1: Numeric ID test
        if url_template:
            numeric = self.test_numeric_id(url_template, id_range, current_id)
            results["numeric_id"] = numeric
            results["steps"].append({"step": "numeric_id", "result": numeric})

        # Step 2: Path manipulation
        if url:
            path = self.test_path_manipulation(url)
            results["path_manipulation"] = path
            results["steps"].append({"step": "path_manipulation", "result": path})

        # Step 3: Parameter pollution
        if url:
            pollution = self.test_parameter_pollution(url)
            results["parameter_pollution"] = pollution
            results["steps"].append({"step": "parameter_pollution", "result": pollution})

        results["vulnerable"] = self.vulnerable
        results["findings"] = self.findings
        results["elapsed_ms"] = int((time.time() - start) * 1000)

        return results


def auto_idor_impl(url: str = "", url_template: str = "", id_range: str = "1-5",
                    current_id: str = "1", method: str = "GET") -> dict:
    """Run automated IDOR scan. Entry point for MCP tool."""
    engine = AutoIDOR(url, method)
    return engine.run_full_scan(url=url, url_template=url_template,
                                 id_range=id_range, current_id=current_id)
