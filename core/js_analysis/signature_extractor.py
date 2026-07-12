"""Static request-signature discovery and replay-script generation."""
from __future__ import annotations
import datetime as _datetime
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_SIGNATURE_NAMES = {"sign", "signature", "sig", "mac", "hash", "digest", "token"}
_OP_PATTERNS = [("sort", r"\.sort\s*\("), ("join", r"\.join\s*\("), ("concat", r"\.concat\s*\(|\s\+\s"), ("hmac_sha256", r"hmac(?:sha)?256|HmacSHA256"), ("hmac_sha1", r"hmac(?:sha)?1|HmacSHA1"), ("sha256", r"sha[-_]?256|SHA256"), ("sha1", r"sha[-_]?1|SHA1"), ("md5", r"\bmd5\s*\(|\.MD5\s*\("), ("base64", r"\bbtoa\s*\(|Base64|base64"), ("urlencode", r"encodeURIComponent\s*\("), ("hex", r"enc\.Hex|toString\s*\(\s*16\s*\)"), ("aes", r"\bAES\b|aes(?:Encrypt|_encrypt)?"), ("des", r"\b(?:DES|TripleDES)\b|desEncrypt"), ("rsa", r"\bRSA\b|JSEncrypt|rsa(?:Sign|Encrypt)"), ("timestamp", r"\b(?:timestamp|timeStamp|Date\.now)\b"), ("nonce", r"\bnonce\b")]

def _functions(source: str) -> list[dict[str, Any]]:
    starts = re.finditer(r"(?:function\s+([\w$]+)\s*\([^)]*\)|(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)\s*{", source)
    results = []
    for match in starts:
        depth, quote, escaped, index = 1, "", False, match.end()
        while index < len(source) and depth:
            char = source[index]
            if quote:
                if escaped: escaped = False
                elif char == "\\": escaped = True
                elif char == quote: quote = ""
            elif char in "'\"`": quote = char
            elif char == "{": depth += 1
            elif char == "}": depth -= 1
            index += 1
        results.append({"name": match.group(1) or match.group(2), "code": source[match.start():index], "offset": match.start()})
    return results

def _operations(code: str) -> list[str]: return [name for name, pattern in _OP_PATTERNS if re.search(pattern, code, re.I)]
def _algorithm(operations: list[str]) -> str:
    return next((name for name in ("hmac_sha256", "hmac_sha1", "sha256", "sha1", "md5", "rsa", "aes", "des") if name in operations), "unknown")

def _key_sources(source: str, code: str) -> list[dict[str, str]]:
    found = []
    patterns = [("local_storage", r"(?:localStorage|sessionStorage)\.getItem\s*\(\s*(['\"])(.*?)\1"), ("cookie", r"document\.cookie"), ("environment", r"(?:process\.env|import\.meta\.env)\.([\w$]+)"), ("server_response", r"(?:response|res|data)\.(?:secret|key|salt|token)"), ("hardcoded", r"\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|SALT|IV))\b\s*=\s*(['\"])(.*?)\2")]
    for origin, pattern in patterns:
        for match in re.finditer(pattern, code + "\n" + source, re.I):
            value = next((group for group in match.groups()[::-1] if group), match.group(0)) if match.groups() else match.group(0)
            item = {"source": origin, "value": value}
            if item not in found: found.append(item)
    return found

def _score(candidate: dict[str, Any], parameter_name: str | None) -> int:
    code, name, score = candidate["code"], candidate["name"].lower(), 0
    if parameter_name and re.search(rf"\b{re.escape(parameter_name)}\b", code, re.I): score += 35
    if re.search(r"hash|md5|sha|hmac|encrypt|sign", code, re.I): score += 30
    if re.search(r"\.sort\s*\(|\.join\s*\(|\.concat\s*\(|\s\+\s", code): score += 20
    if re.search(r"timestamp|nonce|Date\.now", code, re.I): score += 10
    if re.search(r"return\s+", code): score += 5
    if name in _SIGNATURE_NAMES or "sign" in name: score += 20
    return score

def _replay_script(algorithm: str, operations: list[str], key_sources: list[dict[str, str]], target_url: str, parameter_name: str) -> str:
    digest = algorithm.removeprefix("hmac_") if algorithm.startswith("hmac_") else {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}.get(algorithm, "sha256")
    key_hint = key_sources[0]["value"] if key_sources else "REPLACE_WITH_SECRET"
    lines = ['"""Generated signature replay scaffold; validate ordering and secrets."""', "import base64", "import hashlib", "import hmac", "import json", "import urllib.request", "", f"TARGET_URL = {target_url!r}", f"SECRET = {key_hint!r}", "", "def canonicalize(params):", "    return '&'.join(f'{key}={params[key]}' for key in sorted(params))", "", "def calculate_signature(params):", "    payload = canonicalize(params).encode('utf-8')"]
    if algorithm.startswith("hmac_"): lines.append(f"    signature = hmac.new(SECRET.encode('utf-8'), payload, hashlib.{digest}).hexdigest()")
    else: lines.extend(["    payload += SECRET.encode('utf-8')", f"    signature = hashlib.{digest}(payload).hexdigest()"])
    if "base64" in operations: lines.append("    signature = base64.b64encode(signature.encode('ascii')).decode('ascii')")
    lines.extend(["    return signature", "", "def send(params):", "    params = dict(params)", f"    params[{parameter_name!r}] = calculate_signature(params)", "    data = json.dumps(params).encode('utf-8')", "    request = urllib.request.Request(TARGET_URL, data=data, headers={'Content-Type': 'application/json'}, method='POST')", "    with urllib.request.urlopen(request, timeout=15) as response:", "        return response.read().decode('utf-8')", "", "if __name__ == '__main__':", "    print(send({'example': 'value'}))", ""])
    return "\n".join(lines)

def extract_signatures(source: str, parameter_name: str | None = None, observations: list[dict[str, Any]] | None = None, target_url: str = "", output_dir: str | Path | None = None) -> dict[str, Any]:
    observations = observations or []
    observed_names = {str(key).lower() for observation in observations for key in observation.get("added_parameters", observation.get("parameters", {}))}
    detected_names = sorted({name for name in _SIGNATURE_NAMES if re.search(rf"\b{name}\b", source, re.I)} | observed_names)
    selected_name = parameter_name or (detected_names[0] if detected_names else None)
    candidates = _functions(source)
    for candidate in candidates:
        candidate["score"] = _score(candidate, selected_name); candidate["operations"] = _operations(candidate["code"]); candidate["algorithm"] = _algorithm(candidate["operations"]); candidate["key_sources"] = _key_sources(source, candidate["code"]); candidate["line"] = source.count("\n", 0, candidate.pop("offset")) + 1
    top = sorted((candidate for candidate in candidates if candidate["score"] > 0), key=lambda item: (-item["score"], item["line"]))[:3]
    best = top[0] if top else {"algorithm": "unknown", "operations": [], "key_sources": [], "score": 0, "name": None}
    confidence, replay_path, replay_code = min(1.0, best["score"] / 100.0), None, None
    if best["algorithm"] != "unknown":
        replay_code = _replay_script(best["algorithm"], best["operations"], best["key_sources"], target_url, selected_name or "sign")
        if output_dir:
            destination = Path(output_dir); destination.mkdir(parents=True, exist_ok=True)
            host = re.sub(r"[^A-Za-z0-9.-]+", "_", urlparse(target_url).hostname or "target")
            path = destination / f"replay_{host}_{_datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.py"; path.write_text(replay_code, encoding="utf-8"); replay_path = str(path)
    confirmed, inferred, unresolved = [], [], []
    if selected_name and (selected_name.lower() in observed_names or parameter_name): confirmed.append({"type": "signature_parameter", "name": selected_name})
    elif selected_name: inferred.append({"type": "signature_parameter", "name": selected_name})
    if best["algorithm"] != "unknown": inferred.append({"type": "algorithm", "name": best["algorithm"], "candidate": best["name"]})
    else: unresolved.append({"type": "algorithm", "reason": "No cryptographic candidate was statically identifiable"})
    if not best["key_sources"]: unresolved.append({"type": "key_source", "reason": "No key, salt, or secret source was statically identifiable"})
    return {"parameter_name": selected_name, "algorithm": best["algorithm"], "operations": best["operations"], "key_sources": best["key_sources"], "confidence": confidence, "candidates": top, "confirmed": confirmed, "inferred": inferred, "unresolved": unresolved, "replay_script": replay_path, "replay_code": replay_code}

def extract_signature(source: str, parameter_name: str | None = None, observations: list[dict[str, Any]] | None = None, target_url: str = "", output_dir: str | Path | None = None) -> dict[str, Any]: return extract_signatures(source, parameter_name, observations, target_url, output_dir)
analyze_signature = extract_signatures
__all__ = ["extract_signature", "extract_signatures", "analyze_signature"]
