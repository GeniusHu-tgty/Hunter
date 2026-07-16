"""
Hunter v5 — Auto IDOR Engine

Automates Insecure Direct Object Reference detection:
1. Numeric ID manipulation (increment/decrement)
2. UUID/GUID swapping between sessions
3. Response comparison between user contexts
4. Parameter fuzzing for hidden ID fields
"""

import hashlib
import json
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote, urljoin
from core.probe import _get_session
from core.request_broker import LegacyRequestsAdapter, RequestBroker


def _new_isolated_session():
    """Create a cookie-isolated control session even under MCP session injection."""
    return LegacyRequestsAdapter(RequestBroker("sessions/request_broker/isolated"))


class AutoIDOR:
    """Automated IDOR detection engine."""

    _VOLATILE_FIELDS = {
        "csrf",
        "csrf_token",
        "generated_at",
        "nonce",
        "request_id",
        "requestid",
        "server_time",
        "timestamp",
        "trace_id",
        "traceid",
        "updated_at",
    }
    _DENIAL_MARKERS = (
        "access denied",
        "forbidden",
        "login required",
        "not authorized",
        "permission denied",
        "please log in",
        "sign in",
        "unauthorized",
    )
    _SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
    }

    def __init__(self, base_url: str, method: str = "GET",
                 session=None, session2=None, anonymous_session=None,
                 endpoint: str = ""):
        if endpoint:
            self.endpoint = endpoint if endpoint.startswith(("http://", "https://")) else urljoin(
                base_url.rstrip("/") + "/", endpoint.lstrip("/")
            )
        else:
            self.endpoint = base_url
        self.base_url = base_url
        self.method = method.upper()
        self.session = session or _get_session()  # Attacker session
        self.session2 = session2  # Victim session (optional)
        self.anonymous_session = anonymous_session
        self.vulnerable = False
        self.findings = []

    def _send(self, session, url: str, method: str = None, headers: dict = None) -> dict:
        """Send request with given session."""
        try:
            m = (method or self.method).upper()
            kwargs = {
                "headers": headers or {},
                "timeout": 10,
                "allow_redirects": False,
            }
            if hasattr(session, "request"):
                resp = session.request(m, url, **kwargs)
            elif m == "GET":
                resp = session.get(url, **kwargs)
            else:
                resp = session.post(url, **kwargs)
            response_text = str(resp.text or "")
            return {
                "status": resp.status_code,
                "body": response_text[:5000],
                "length": len(response_text),
                "headers": dict(resp.headers),
                "_semantic": self._normalize_body(response_text),
            }
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    @classmethod
    def _normalize_json(cls, value):
        if isinstance(value, dict):
            return {
                key: cls._normalize_json(item)
                for key, item in sorted(value.items())
                if str(key).casefold() not in cls._VOLATILE_FIELDS
            }
        if isinstance(value, list):
            return [cls._normalize_json(item) for item in value]
        return value

    @classmethod
    def _normalize_body(cls, body: str) -> str:
        stripped = str(body or "").strip()
        if not stripped:
            return ""
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            return re.sub(r"\s+", " ", stripped)
        return json.dumps(
            cls._normalize_json(parsed),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def _public_response(cls, response: dict) -> dict:
        public = {
            key: value
            for key, value in response.items()
            if not str(key).startswith("_")
        }
        headers = public.get("headers")
        if isinstance(headers, dict):
            public["headers"] = {
                key: "REDACTED" if str(key).casefold() in cls._SENSITIVE_HEADERS else value
                for key, value in headers.items()
            }
        return public

    @classmethod
    def _is_meaningful_success(cls, response: dict) -> bool:
        status = int(response.get("status") or 0)
        body = str(response.get("body") or "")
        if not 200 <= status < 300 or not response.get("_semantic"):
            return False
        return not any(marker in body.casefold() for marker in cls._DENIAL_MARKERS)

    @staticmethod
    def _semantic_digest(response: dict) -> str:
        semantic = str(response.get("_semantic") or "")
        if not semantic:
            return ""
        return hashlib.sha256(semantic.encode("utf-8")).hexdigest()

    @classmethod
    def _response_contains_identifier(cls, response: dict, identifier: str) -> bool:
        expected = str(identifier)
        semantic = str(response.get("_semantic") or "")
        if not semantic or not expected:
            return False
        try:
            parsed = json.loads(semantic)
        except (TypeError, ValueError, json.JSONDecodeError):
            return bool(re.search(
                rf"(?<![A-Za-z0-9_-]){re.escape(expected)}(?![A-Za-z0-9_-])",
                semantic,
            ))

        def matches(value) -> bool:
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                return str(value) == expected
            if isinstance(value, list):
                return any(matches(item) for item in value)
            return False

        def walk(value) -> bool:
            if isinstance(value, dict):
                for key, item in value.items():
                    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
                    identity_field = (
                        normalized in {"id", "ids", "guid", "guids", "uuid", "uuids"}
                        or normalized.endswith("_id")
                        or normalized.endswith("_ids")
                        or (normalized.endswith("id") and len(normalized) > 2)
                    )
                    if identity_field and matches(item):
                        return True
                    if isinstance(item, (dict, list)) and walk(item):
                        return True
                return False
            if isinstance(value, list):
                return any(walk(item) for item in value if isinstance(item, (dict, list)))
            return False

        return walk(parsed)

    @classmethod
    def _control_summary(cls, response: dict, owner_digest: str = "") -> dict:
        digest = cls._semantic_digest(response)
        return {
            "status": int(response.get("status") or 0),
            "body_length": int(response.get("length") or len(str(response.get("body") or ""))),
            "semantic_digest": digest,
            "matches_owner": bool(owner_digest and digest == owner_digest and cls._is_meaningful_success(response)),
        }

    def test_authorization_differential(
        self,
        url_template: str,
        attacker_id: str,
        owner_id: str,
        attacker_cookie: str = "",
        owner_cookie: str = "",
        repetitions: int = 3,
    ) -> dict:
        """Prove cross-user reads with owner, attacker-own, and anonymous controls."""
        controls = {
            "attacker_own": {},
            "owner": {},
            "anonymous": {},
            "cross_user": {
                "attempts": 0,
                "semantic_matches": 0,
                "semantic_digests": [],
            },
        }

        def result(classification: str, reason: str, evidence=None) -> dict:
            return {
                "test": "authorization_differential",
                "target": url_template,
                "vulnerable": classification == "verified",
                "classification": classification,
                "reason": reason,
                "controls": controls,
                "evidence": evidence or {},
                "findings": list(self.findings),
            }

        if "{id}" not in str(url_template):
            return result("inconclusive", "The endpoint must contain an {id} resource placeholder")
        if not attacker_id or not owner_id or str(attacker_id) == str(owner_id):
            return result("inconclusive", "Distinct attacker and owner resource IDs are required")
        try:
            repetitions = int(repetitions)
        except (TypeError, ValueError):
            return result("inconclusive", "Repetitions must be an integer between 1 and 5")
        if not 1 <= repetitions <= 5:
            return result("inconclusive", "Repetitions must be between 1 and 5")

        attacker_url = url_template.replace("{id}", quote(str(attacker_id), safe=""))
        owner_url = url_template.replace("{id}", quote(str(owner_id), safe=""))
        attacker_headers = {"Cookie": attacker_cookie} if attacker_cookie else {}
        owner_headers = {"Cookie": owner_cookie} if owner_cookie else {}

        attacker_control = self._send(self.session, attacker_url, headers=attacker_headers)
        owner_session = self.session2 or _new_isolated_session()
        owner_control = self._send(owner_session, owner_url, headers=owner_headers)
        owner_digest = self._semantic_digest(owner_control)
        controls["attacker_own"] = self._control_summary(attacker_control, owner_digest)
        controls["owner"] = self._control_summary(owner_control, owner_digest)

        def build_evidence(response: dict, matches: int, owner_data_returned: bool) -> dict:
            return {
                "request": {
                    "method": self.method,
                    "url": owner_url,
                    "headers": {"Cookie": "REDACTED"} if attacker_cookie else {},
                },
                "response": self._public_response(response),
                "baseline_response": self._public_response(attacker_control),
                "payload": str(owner_id),
                "reproduction_count": matches,
                "metadata": {
                    "request_user": str(attacker_id),
                    "resource_owner": str(owner_id),
                    "owner_data_returned": owner_data_returned,
                    "attacker_resource_url": attacker_url,
                    "owner_resource_url": owner_url,
                    "control_matrix": controls,
                },
            }

        if not self._is_meaningful_success(owner_control):
            evidence = build_evidence({}, 0, False)
            return result("inconclusive", "Owner control was not an authenticated successful response", evidence)
        if not self._is_meaningful_success(attacker_control):
            evidence = build_evidence({}, 0, False)
            return result("inconclusive", "Attacker own-resource control was not successful", evidence)

        anonymous_session = self.anonymous_session or _new_isolated_session()
        anonymous_control = self._send(anonymous_session, owner_url, headers={})
        controls["anonymous"] = self._control_summary(anonymous_control, owner_digest)

        if controls["attacker_own"]["matches_owner"]:
            evidence = build_evidence({}, 0, False)
            return result("refuted", "Attacker-own and owner controls are identical generic responses", evidence)
        if controls["anonymous"]["matches_owner"]:
            evidence = build_evidence(anonymous_control, 0, False)
            return result("refuted", "The owner resource is public to the anonymous control", evidence)
        if not self._response_contains_identifier(owner_control, str(owner_id)):
            evidence = build_evidence({}, 0, False)
            return result("inconclusive", "Owner control was not bound to the requested owner resource ID", evidence)

        matched_response = {}
        semantic_digests = []
        matches = 0
        for _ in range(repetitions):
            probe = self._send(self.session, owner_url, headers=attacker_headers)
            controls["cross_user"]["attempts"] += 1
            probe_digest = self._semantic_digest(probe)
            semantic_digests.append(probe_digest)
            if (
                self._is_meaningful_success(probe)
                and probe_digest == owner_digest
                and self._response_contains_identifier(probe, str(owner_id))
            ):
                matches += 1
                if not matched_response:
                    matched_response = probe

        controls["cross_user"]["semantic_matches"] = matches
        controls["cross_user"]["semantic_digests"] = semantic_digests
        owner_data_returned = matches > 0
        evidence = build_evidence(matched_response, matches, owner_data_returned)

        if matches == repetitions and repetitions >= 3:
            self.vulnerable = True
            self.findings.append({
                "type": "idor_cross_user_verified",
                "severity": "high",
                "url": owner_url,
                "attacker_id": str(attacker_id),
                "owner_id": str(owner_id),
                "reproductions": matches,
            })
            verified = result(
                "verified",
                "Attacker session repeatedly returned the owner-bound resource while anonymous access was denied",
                evidence,
            )
            verified["findings"] = list(self.findings)
            return verified
        if matches:
            return result(
                "likely",
                "Owner-bound data was observed but did not satisfy the three-repeat verification gate",
                evidence,
            )
        return result(
            "refuted",
            "Attacker session did not return the owner-bound resource",
            evidence,
        )

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

    def test_cookie_role_tampering(self, url: str, cookies: dict = None) -> dict:
        """Test privilege escalation via cookie manipulation.

        Changes role/admin/isAdmin cookies to escalate privileges.
        """
        if not cookies:
            return {"error": "No cookies provided"}

        tamper_tests = [
            ("role", "user", "admin"),
            ("isAdmin", "false", "true"),
            ("isAdmin", "0", "1"),
            ("admin", "false", "true"),
            ("admin", "0", "1"),
            ("access_level", "1", "99"),
            ("privilege", "low", "high"),
        ]

        results = []
        for cookie_name, original, tampered in tamper_tests:
            if cookie_name in cookies:
                # Test with tampered value
                tampered_cookies = dict(cookies)
                tampered_cookies[cookie_name] = tampered

                result = self._send(self.session, url, headers={"Cookie": "; ".join(f"{k}={v}" for k, v in tampered_cookies.items())})

                # Check if response differs (privilege escalation)
                if result.get("status") == 200:
                    # Check for admin-specific content
                    body = result.get("body", "").lower()
                    if any(x in body for x in ["admin", "delete", "manage", "settings", "panel"]):
                        self.vulnerable = True
                        self.findings.append({
                            "type": "cookie_role_tampering",
                            "cookie": cookie_name,
                            "original": original,
                            "tampered": tampered,
                        })
                        results.append({
                            "cookie": cookie_name,
                            "tampered_value": tampered,
                            "vulnerable": True,
                            "status": result["status"],
                        })

        return {"tested": len(results), "vulnerable": self.vulnerable, "results": results}

    def test_hidden_params(self, url: str) -> dict:
        """Test for hidden parameters that control access.

        Tries common parameter names in POST body.
        """
        hidden_params = [
            "admin", "isAdmin", "is_admin", "role", "access_level",
            "privilege", "permission", "debug", "test", "internal",
            "api_key", "token", "secret",
        ]

        results = []
        for param in hidden_params:
            # Test with admin/true values
            for value in ["admin", "true", "1", "yes"]:
                result = self._send(self.session, url, method="POST",
                                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                if result.get("status") == 200:
                    body = result.get("body", "").lower()
                    if any(x in body for x in ["admin", "manage", "settings"]):
                        results.append({"param": param, "value": value, "vulnerable": True})

        return {"tested": len(hidden_params), "results": results}

    def run_full_scan(self, url: str = "", url_template: str = "",
                      id_range: str = "1-5", current_id: str = "1",
                      attacker_cookie: str = "", owner_cookie: str = "",
                      attacker_id: str = "", owner_id: str = "",
                      repetitions: int = 3) -> dict:
        """Run complete IDOR scan."""
        differential_template = url_template or (url if "{id}" in url else "")
        if differential_template and attacker_id and owner_id:
            return self.test_authorization_differential(
                url_template=differential_template,
                attacker_id=attacker_id,
                owner_id=owner_id,
                attacker_cookie=attacker_cookie,
                owner_cookie=owner_cookie,
                repetitions=repetitions,
            )

        start = time.time()
        url = url or self.endpoint
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
                   current_id: str = "1", method: str = "GET", cookie: str = "",
                   owner_cookie: str = "", attacker_id: str = "",
                   owner_id: str = "", repetitions: int = 3, session=None,
                   owner_session=None, anonymous_session=None) -> dict:
    """Run automated IDOR scan. Entry point for MCP tool."""
    engine = AutoIDOR(
        url or url_template,
        method,
        session=session,
        session2=owner_session,
        anonymous_session=anonymous_session,
    )
    return engine.run_full_scan(url=url, url_template=url_template,
                                id_range=id_range, current_id=current_id,
                                attacker_cookie=cookie,
                                owner_cookie=owner_cookie,
                                attacker_id=attacker_id,
                                owner_id=owner_id,
                                repetitions=repetitions)


@dataclass(frozen=True)
class Identity:
    """An isolated authorization principal for a differential proof."""

    name: str
    cookie: str = ""
    bearer_token: str = ""
    resource_id: str = ""


@dataclass(frozen=True)
class AuthorizationProofPlan:
    """Declarative BOLA/BFLA proof inputs, without changing legacy scans."""

    request_template: Mapping[str, Any]
    oracle_template: Mapping[str, Any]
    attacker: Identity
    owner: Identity
    anonymous: Identity
    cleanup_template: Mapping[str, Any] | None = None
    repetitions: int = 3
    operation: str = "read"
    vulnerability_type: str = "bola"


_PROOF_SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key",
}


def _render_proof_template(value: Any, resource_id: str) -> Any:
    if isinstance(value, str):
        return value.replace("{{resource_id}}", resource_id)
    if isinstance(value, list):
        return [_render_proof_template(item, resource_id) for item in value]
    if isinstance(value, Mapping):
        return {key: _render_proof_template(item, resource_id) for key, item in value.items()}
    return value


def _proof_request(session, template: Mapping[str, Any], identity: Identity, resource_id: str) -> dict:
    spec = _render_proof_template(deepcopy(dict(template)), resource_id)
    headers = dict(spec.pop("headers", {}) or {})
    if identity.bearer_token:
        headers["Authorization"] = f"Bearer {identity.bearer_token}"
    if identity.cookie:
        headers.setdefault("Cookie", identity.cookie)
    method = str(spec.pop("method", "GET")).upper()
    url = str(spec.pop("url"))
    response = session.request(method, url, headers=headers, timeout=10, allow_redirects=False, **spec)
    return {
        "status": int(response.status_code),
        "body": str(response.text or ""),
        "headers": dict(getattr(response, "headers", {}) or {}),
        "request": {"method": method, "url": url, "headers": headers, **spec},
    }


def _proof_json_pointer(body: str, pointer: str) -> Any:
    value: Any = json.loads(body)
    for part in pointer.lstrip("/").split("/"):
        if not part:
            continue
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _redact_proof(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: "REDACTED" if str(key).casefold() in _PROOF_SENSITIVE_HEADERS else _redact_proof(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_proof(item) for item in value]
    return value


def _proof_allowed(result: Mapping[str, Any]) -> bool:
    if not 200 <= int(result.get("status", 0)) < 300:
        return False
    try:
        parsed = json.loads(str(result.get("body", "")))
    except json.JSONDecodeError:
        return True
    return not bool(parsed.get("errors")) if isinstance(parsed, Mapping) else True


def verify_authorization_plan(plan: AuthorizationProofPlan, sessions: Mapping[str, Any]) -> dict:
    """Verify BOLA/BFLA only with controls, an effect oracle, and cleanup."""

    if plan.operation != "write" or not plan.cleanup_template:
        return {"classification": "inconclusive", "vulnerable": False,
                "reason": "write authorization proofs require an explicit cleanup template", "rounds": []}
    if plan.vulnerability_type not in {"bola", "bfla"}:
        raise ValueError("vulnerability_type must be 'bola' or 'bfla'")
    if not 1 <= int(plan.repetitions) <= 5:
        raise ValueError("repetitions must be between 1 and 5")
    missing = [name for name in ("attacker", "owner", "anonymous") if name not in sessions]
    if missing:
        raise ValueError(f"missing identity sessions: {', '.join(missing)}")
    if not plan.owner.resource_id or plan.owner.resource_id == plan.attacker.resource_id:
        return {"classification": "inconclusive", "vulnerable": False,
                "reason": "attacker and owner resources must be distinct", "rounds": []}

    owner_id = plan.owner.resource_id
    oracle_pointer = str(plan.oracle_template.get("json_pointer", ""))
    expected_after = plan.oracle_template.get("expected_after")
    if not oracle_pointer or expected_after is None:
        return {"classification": "inconclusive", "vulnerable": False,
                "reason": "write authorization proofs require an oracle pointer and expected_after", "rounds": []}

    owner_action = _proof_request(sessions["owner"], plan.request_template, plan.owner, owner_id)
    owner_cleanup = _proof_request(sessions["owner"], plan.cleanup_template, plan.owner, owner_id)
    anonymous_action = _proof_request(sessions["anonymous"], plan.request_template, plan.anonymous, owner_id)
    owner_allowed = _proof_allowed(owner_action) and _proof_allowed(owner_cleanup)
    anonymous_denied = not _proof_allowed(anonymous_action)
    rounds = []
    for index in range(int(plan.repetitions)):
        before = _proof_request(sessions["attacker"], plan.oracle_template, plan.attacker, owner_id)
        action = _proof_request(sessions["attacker"], plan.request_template, plan.attacker, owner_id)
        after = _proof_request(sessions["attacker"], plan.oracle_template, plan.attacker, owner_id)
        cleanup = _proof_request(sessions["owner"], plan.cleanup_template, plan.owner, owner_id)
        try:
            before_value = _proof_json_pointer(before["body"], oracle_pointer)
            after_value = _proof_json_pointer(after["body"], oracle_pointer)
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            before_value = after_value = None
        rounds.append({
            "round": index + 1,
            "attacker_allowed": _proof_allowed(action),
            "cleanup_allowed": _proof_allowed(cleanup),
            "oracle_before": before_value,
            "oracle_after": after_value,
            "effect_confirmed": before_value != expected_after and after_value == expected_after,
        })
    reproduced = sum(item["attacker_allowed"] and item["cleanup_allowed"] and item["effect_confirmed"] for item in rounds)
    verified = owner_allowed and anonymous_denied and reproduced == len(rounds) and len(rounds) >= 3
    classification = "verified" if verified else "likely" if reproduced else "refuted"
    if not owner_allowed or not anonymous_denied:
        classification = "inconclusive"
    evidence = {
        "request": _redact_proof({"template": dict(plan.request_template)}),
        "response": {"rounds": len(rounds)},
        "baseline_response": {},
        "payload": "authorization-proof",
        "reproduction_count": reproduced,
        "metadata": {
            "owner_control": owner_allowed,
            "anonymous_control": anonymous_denied,
            "write_effect_oracle": bool(reproduced),
            "operation": plan.operation,
            "request_user": plan.attacker.name,
            "resource_owner": plan.owner.name,
            "owner_data_returned": bool(reproduced),
        },
    }
    return {"classification": classification, "vulnerable": verified,
            "vulnerability_type": plan.vulnerability_type,
            "controls": {"owner": {"allowed": owner_allowed}, "anonymous": {"denied": anonymous_denied}},
            "rounds": rounds, "evidence": evidence}
