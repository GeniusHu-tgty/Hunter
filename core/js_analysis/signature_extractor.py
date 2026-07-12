"""Static request-signature discovery and replay-script generation."""
from __future__ import annotations
import ast
import datetime as _datetime
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_SIGNATURE_NAMES = {"sign", "signature", "sig", "mac", "hash", "digest", "token"}
_REQUEST_PLACEMENTS = {"query", "json", "body", "header"}
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

def _operations(code: str) -> list[str]:
    matches = []
    semantic_order = {
        "timestamp": 5, "nonce": 5, "sort": 10, "join": 20, "concat": 30,
        "urlencode": 40, "md5": 50, "sha1": 50, "sha256": 50,
        "hmac_sha1": 50, "hmac_sha256": 50, "aes": 60, "des": 60,
        "rsa": 60, "hex": 70, "base64": 70,
    }
    for name, pattern in _OP_PATTERNS:
        match = re.search(pattern, code, re.I)
        if match:
            matches.append((semantic_order.get(name, 99), match.start(), name))
    operations = [name for _, _, name in sorted(matches)]
    if "hmac_sha256" in operations and "sha256" in operations:
        operations.remove("sha256")
    if "hmac_sha1" in operations and "sha1" in operations:
        operations.remove("sha1")
    return operations
def _algorithm(operations: list[str]) -> str:
    crypto = [name for name in operations if name in {"hmac_sha256", "hmac_sha1", "sha256", "sha1", "md5", "rsa", "aes", "des"}]
    if len(crypto) > 1:
        return "nested"
    return crypto[0] if crypto else "unknown"

def _key_sources(source: str, code: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    corpus = code + "\n" + source
    reference_patterns = [
        ("local_storage", r"localStorage\.getItem\s*\(\s*(['\"])(.*?)\1"),
        ("session_storage", r"sessionStorage\.getItem\s*\(\s*(['\"])(.*?)\1"),
        ("environment", r"(?:process\.env|import\.meta\.env)\.([\w$]+)"),
    ]
    for origin, pattern in reference_patterns:
        for match in re.finditer(pattern, corpus, re.I):
            reference = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
            item = {"source": origin, "reference": reference}
            if item not in found:
                found.append(item)
    if re.search(r"\bdocument\.cookie\b", corpus):
        found.append({"source": "cookie", "reference": "document.cookie"})
    for match in re.finditer(r"\b(?:response|res|data)\.(secret|key|salt|token)\b", corpus, re.I):
        item = {"source": "server_response", "reference": match.group(0)}
        if item not in found:
            found.append(item)
    for match in re.finditer(r"\b[A-Z][A-Z0-9_]*(?:KEY|SECRET|SALT|IV)\b\s*=\s*(['\"])(.*?)\1", corpus):
        item = {"source": "hardcoded", "value": match.group(2)}
        if item not in found:
            found.append(item)
    for match in re.finditer(r"(?:\+|\.concat\s*\()\s*(['\"])([^'\"]{3,})\1", code):
        item = {"source": "hardcoded", "value": match.group(2)}
        if item not in found:
            found.append(item)
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

def _split_top_level(value: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == delimiter and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def _call_arguments(expression: str, names: tuple[str, ...]) -> tuple[list[str], str, str] | None:
    name_pattern = "|".join(re.escape(name) for name in names)
    match = re.search(rf"(?P<name>{name_pattern})\s*\(", expression, re.I)
    if not match:
        return None
    depth = 1
    quote = ""
    escaped = False
    index = match.end()
    while index < len(expression) and depth:
        char = expression[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        index += 1
    if depth:
        return None
    prefix = expression[:match.start()].strip()
    suffix = expression[index:].strip()
    arguments = _split_top_level(expression[match.end():index - 1], ",")
    return arguments, prefix, suffix


def _literal_string(value: str) -> str | None:
    try:
        parsed = ast.literal_eval(value.strip())
    except (SyntaxError, ValueError):
        return None
    return parsed if isinstance(parsed, str) else None


def _canonicalization_ir(expression: str) -> dict[str, str] | None:
    match = re.fullmatch(
        r"Object\.keys\s*\(\s*[A-Za-z_$][\w$]*\s*\)"
        r"\s*\.sort\s*\(\s*\)\s*\.join\s*\(\s*(['\"])(.*?)\1\s*\)",
        expression.strip(),
        re.S,
    )
    if not match:
        return None
    return {
        "kind": "object_keys",
        "sort": "lexicographic",
        "projection": "key",
        "delimiter": match.group(2),
    }


def _select_key_source(key_sources: list[dict[str, str]], literal: str | None = None) -> dict[str, str] | None:
    if literal is not None:
        return {"source": "hardcoded", "value": literal}
    return key_sources[0] if key_sources else None


def _signature_ir(code: str, algorithm: str, key_sources: list[dict[str, str]]) -> dict[str, Any] | None:
    return_match = re.search(r"\breturn\s+(.+?);", code, re.S)
    if not return_match:
        return None
    expression = return_match.group(1).strip()
    if algorithm in {"md5", "sha1", "sha256"}:
        call = _call_arguments(expression, (algorithm, algorithm.upper(), f"CryptoJS.{algorithm.upper()}"))
        if not call:
            return None
        arguments, prefix, suffix = call
        if prefix or (suffix and not re.fullmatch(r"\.toString\s*\([^)]*\)", suffix)):
            return None
        if len(arguments) != 1:
            return None
        components = _split_top_level(arguments[0], "+")
        canonicalization = _canonicalization_ir(components[0])
        if not canonicalization or len(components) > 2:
            return None
        secret_source = None
        secret_mode = "none"
        if len(components) == 2:
            secret_source = _select_key_source(key_sources, _literal_string(components[1]))
            secret_mode = "suffix"
        return {
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "secret_mode": secret_mode,
            "secret_source": secret_source,
        }
    if algorithm in {"hmac_sha1", "hmac_sha256"}:
        call_name = "HmacSHA1" if algorithm == "hmac_sha1" else "HmacSHA256"
        call = _call_arguments(expression, (call_name, f"CryptoJS.{call_name}"))
        if not call:
            return None
        arguments, prefix, suffix = call
        if prefix or (suffix and not re.fullmatch(r"\.toString\s*\([^)]*\)", suffix)):
            return None
        if len(arguments) != 2:
            return None
        canonicalization = _canonicalization_ir(arguments[0])
        if not canonicalization:
            return None
        return {
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "secret_mode": "hmac_key",
            "secret_source": _select_key_source(key_sources, _literal_string(arguments[1])),
        }
    return None


def _observed_request_context(observations: list[dict[str, Any]]) -> dict[str, Any] | None:
    for observation in observations:
        context = observation.get("request_context")
        if not isinstance(context, dict):
            continue
        if not {"method", "url", "headers", "placement"} <= context.keys():
            continue
        method = context["method"]
        url = context["url"]
        headers = context["headers"]
        placement = context["placement"]
        if not isinstance(method, str) or not method:
            continue
        if not isinstance(url, str) or not url:
            continue
        if not isinstance(headers, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in headers.items()
        ):
            continue
        if placement not in _REQUEST_PLACEMENTS:
            continue
        return {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "placement": placement,
        }
    return None


def _replay_script(
    signature_ir: dict[str, Any],
    parameter_name: str,
    request_context: dict[str, Any] | None = None,
) -> str:
    algorithm = signature_ir["algorithm"]
    canonicalization = signature_ir["canonicalization"]
    secret_source = signature_ir.get("secret_source")
    digest = algorithm.removeprefix("hmac_")
    lines = [
        (
            '"""Generated transport replay from observed request context."""'
            if request_context
            else '"""Generated signing scaffold from recovered canonicalization IR."""'
        ),
        "import hashlib",
    ]
    if algorithm.startswith("hmac_"):
        lines.append("import hmac")
    needs_secret = signature_ir["secret_mode"] != "none"
    if needs_secret and (not secret_source or secret_source.get("source") != "hardcoded"):
        lines.append("import os")
    if request_context:
        if request_context["placement"] == "json":
            lines.append("import json")
        lines.append("import urllib.request")
        if request_context["placement"] in {"query", "body"}:
            lines.append("import urllib.parse")
    lines.append("")
    if needs_secret:
        if secret_source and secret_source.get("source") == "hardcoded":
            lines.append(f"SECRET = {secret_source['value']!r}")
        else:
            lines.append('SECRET = os.environ.get("HUNTER_REPLAY_SECRET", "REPLACE_WITH_SECRET")')
    if request_context:
        lines.extend([
            f"REQUEST_METHOD = {request_context['method']!r}",
            f"REQUEST_URL = {request_context['url']!r}",
            f"REQUEST_HEADERS = {request_context['headers']!r}",
        ])
    lines.extend([
        "",
        "def canonicalize(params):",
    ])
    if canonicalization["projection"] == "key":
        lines.append(
            f"    return {canonicalization['delimiter']!r}.join("
            "sorted((str(key) for key in params), "
            "key=lambda value: value.encode('utf-16-be', 'surrogatepass')))"
        )
    else:
        raise ValueError("unsupported canonicalization projection")
    lines.extend(["", "def calculate_signature(params):", "    payload = canonicalize(params)"])
    if signature_ir["secret_mode"] == "suffix":
        lines.append("    payload += SECRET")
    lines.append("    payload_bytes = payload.encode('utf-8')")
    if algorithm.startswith("hmac_"):
        lines.append(f"    return hmac.new(SECRET.encode('utf-8'), payload_bytes, hashlib.{digest}).hexdigest()")
    else:
        lines.append(f"    return hashlib.{digest}(payload_bytes).hexdigest()")
    if request_context:
        placement = request_context["placement"]
        lines.extend([
            "",
            "def send(params):",
            "    signed_params = dict(params)",
            f"    signed_params[{parameter_name!r}] = calculate_signature(params)",
            "    url = REQUEST_URL",
            "    headers = dict(REQUEST_HEADERS)",
            "    data = None",
        ])
        if placement == "query":
            lines.extend([
                "    parsed_url = urllib.parse.urlsplit(url)",
                "    query = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)",
                "    query.extend((str(key), str(value)) for key, value in signed_params.items())",
                "    url = urllib.parse.urlunsplit((",
                "        parsed_url.scheme,",
                "        parsed_url.netloc,",
                "        parsed_url.path,",
                "        urllib.parse.urlencode(query),",
                "        parsed_url.fragment,",
                "    ))",
            ])
        elif placement == "json":
            lines.append("    data = json.dumps(signed_params, separators=(',', ':')).encode('utf-8')")
        elif placement == "body":
            lines.append("    data = urllib.parse.urlencode(signed_params).encode('utf-8')")
        elif placement == "header":
            lines.append("    headers.update({str(key): str(value) for key, value in signed_params.items()})")
        lines.extend([
            "    request = urllib.request.Request(",
            "        url,",
            "        data=data,",
            "        headers=headers,",
            "        method=REQUEST_METHOD,",
            "    )",
            "    with urllib.request.urlopen(request, timeout=15) as response:",
            "        return response.read().decode('utf-8')",
        ])
    lines.append("")
    return "\n".join(lines)

def extract_signatures(source: str, parameter_name: str | None = None, observations: list[dict[str, Any]] | None = None, target_url: str = "", output_dir: str | Path | None = None) -> dict[str, Any]:
    observations = observations or []
    request_context = _observed_request_context(observations)
    observed_names = {str(key).lower() for observation in observations for key in observation.get("added_parameters", observation.get("parameters", {}))}
    detected_names = sorted({name for name in _SIGNATURE_NAMES if re.search(rf"\b{name}\b", source, re.I)} | observed_names)
    selected_name = parameter_name or (detected_names[0] if detected_names else None)
    candidates = _functions(source)
    for candidate in candidates:
        candidate["score"] = _score(candidate, selected_name)
        candidate["operations"] = _operations(candidate["code"])
        candidate["algorithm"] = _algorithm(candidate["operations"])
        candidate["key_sources"] = _key_sources(source, candidate["code"])
        candidate["signature_ir"] = _signature_ir(candidate["code"], candidate["algorithm"], candidate["key_sources"])
        candidate["canonicalization"] = candidate["signature_ir"]["canonicalization"] if candidate["signature_ir"] else None
        candidate["line"] = source.count("\n", 0, candidate.pop("offset")) + 1
    top = sorted((candidate for candidate in candidates if candidate["score"] > 0), key=lambda item: (-item["score"], item["line"]))[:3]
    best = top[0] if top else {"algorithm": "unknown", "operations": [], "key_sources": [], "score": 0, "name": None, "signature_ir": None, "canonicalization": None}
    confidence, replay_path, replay_code = min(1.0, best["score"] / 100.0), None, None
    replay_status = "unavailable"
    replayable_algorithms = {"md5", "sha1", "sha256", "hmac_sha1", "hmac_sha256"}
    if best["algorithm"] in replayable_algorithms and best["signature_ir"]:
        replay_code = _replay_script(
            best["signature_ir"],
            selected_name or "sign",
            request_context=request_context,
        )
        replay_status = "transport-replay" if request_context else "signing-scaffold"
        if output_dir:
            destination = Path(output_dir); destination.mkdir(parents=True, exist_ok=True)
            replay_url = request_context["url"] if request_context else target_url
            host = re.sub(r"[^A-Za-z0-9.-]+", "_", urlparse(replay_url).hostname or "target")
            path = destination / f"replay_{host}_{_datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.py"; path.write_text(replay_code, encoding="utf-8"); replay_path = str(path)
    confirmed, inferred, unresolved = [], [], []
    if selected_name and (selected_name.lower() in observed_names or parameter_name): confirmed.append({"type": "signature_parameter", "name": selected_name})
    elif selected_name: inferred.append({"type": "signature_parameter", "name": selected_name})
    if best["algorithm"] != "unknown": inferred.append({"type": "algorithm", "name": best["algorithm"], "candidate": best["name"]})
    else: unresolved.append({"type": "algorithm", "reason": "No cryptographic candidate was statically identifiable"})
    if best["algorithm"] in replayable_algorithms and not best["signature_ir"]:
        unresolved.append({"type": "canonicalization", "reason": "No faithful canonicalization IR was recovered"})
    if best["algorithm"] not in replayable_algorithms and best["algorithm"] != "unknown":
        unresolved.append({"type": "replay_blocked", "reason": f"{best['algorithm']} requires recovered mode, padding, key, IV, and encoding details"})
    signature_ir = best.get("signature_ir")
    missing_inputs = []
    if best["algorithm"] in replayable_algorithms and signature_ir and not request_context:
        missing_inputs.append("request_context")
    secret_source = signature_ir.get("secret_source") if signature_ir else None
    if signature_ir and signature_ir["secret_mode"] != "none":
        if not secret_source:
            missing_inputs.append("secret_or_salt")
        elif secret_source.get("source") != "hardcoded":
            missing_inputs.append(f"secret_from_{secret_source['source']}")
    assumptions = []
    if best.get("canonicalization"):
        assumptions.append("Replay preserves the recovered Object.keys(...).sort().join(...) projection and delimiter")
    if replay_status == "signing-scaffold":
        assumptions.append("No HTTP transport is generated without a complete observed request_context")
    elif replay_status == "transport-replay":
        assumptions.append("HTTP transport preserves the observed method, URL, headers, and parameter placement")
    return {"parameter_name": selected_name, "algorithm": best["algorithm"], "operations": best["operations"], "algorithm_steps": [{"order": index + 1, "operation": operation} for index, operation in enumerate(best["operations"])], "canonicalization": best.get("canonicalization"), "key_sources": best["key_sources"], "confidence": confidence, "candidates": top, "confirmed": confirmed, "inferred": inferred, "unresolved": unresolved, "replay_status": replay_status, "request_context": request_context, "assumptions": assumptions, "missing_inputs": missing_inputs, "replay_script": replay_path, "replay_code": replay_code}

def extract_signature(source: str, parameter_name: str | None = None, observations: list[dict[str, Any]] | None = None, target_url: str = "", output_dir: str | Path | None = None) -> dict[str, Any]: return extract_signatures(source, parameter_name, observations, target_url, output_dir)
analyze_signature = extract_signatures
__all__ = ["extract_signature", "extract_signatures", "analyze_signature"]
