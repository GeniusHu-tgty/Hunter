"""Conservative static extraction of client-side API usage."""
from __future__ import annotations
import re
from typing import Any

def _line(source: str, offset: int) -> int: return source.count("\n", 0, offset) + 1

def _balanced(source: str, opening: int) -> str:
    depth, quote, escaped = 0, "", False
    for index in range(opening, len(source)):
        char = source[index]
        if quote:
            if escaped: escaped = False
            elif char == "\\": escaped = True
            elif char == quote: quote = ""
            continue
        if char in "'\"`": quote = char
        elif char in "({[": depth += 1
        elif char in ")}]":
            depth -= 1
            if depth == 0: return source[opening + 1:index]
    return source[opening + 1:]

def _split(text: str) -> list[str]:
    parts, start, depth, quote, escaped = [], 0, 0, "", False
    for index, char in enumerate(text):
        if quote:
            if escaped: escaped = False
            elif char == "\\": escaped = True
            elif char == quote: quote = ""
        elif char in "'\"`": quote = char
        elif char in "({[": depth += 1
        elif char in ")}]": depth -= 1
        elif char == "," and depth == 0: parts.append(text[start:index].strip()); start = index + 1
    parts.append(text[start:].strip()); return parts

def _literal(expression: str) -> tuple[str, str, list[str]]:
    expression = expression.strip()
    if len(expression) >= 2 and expression[0] in "'\"`" and expression[-1] == expression[0]:
        raw = expression[1:-1]; variables = re.findall(r"\$\{\s*([^}]+?)\s*\}", raw)
        return re.sub(r"\$\{\s*([^}]+?)\s*\}", r"{\1}", raw), ("inferred" if variables else "confirmed"), variables
    strings = re.findall(r"['\"]([^'\"]*)['\"]", expression)
    variables = re.findall(r"\b[A-Za-z_$][\w$]*\b", re.sub(r"['\"][^'\"]*['\"]", "", expression))
    if strings and "+" in expression: return "".join(strings) + "".join("{" + value + "}" for value in variables), "inferred", variables
    return expression, "unresolved", variables or [expression]

def _object_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?:^|[,{{])\s*['\"]?{re.escape(key)}['\"]?\s*:\s*(?:(['\"])(.*?)\1|(`)(.*?)`|([^,}}]+))", text, re.I | re.S)
    return next((value.strip() for value in match.groups()[1:] if value is not None), None) if match else None

def extract_api(source: str, source_name: str = "bundle.js") -> dict[str, Any]:
    endpoints, websockets, routes, auth, unresolved = [], [], [], [], []
    def location(offset: int) -> dict[str, Any]: return {"source": source_name, "line": _line(source, offset), "offset": offset}
    def add(kind: str, method: str, expression: str, offset: int, options: str = "") -> None:
        url, confidence, parameters = _literal(expression)
        item = {"kind": kind, "method": method.upper(), "url": url, "parameters": parameters, "headers": _object_value(options, "headers"), "body": _object_value(options, "body") or _object_value(options, "data"), "authentication": [], "confidence": confidence, "location": location(offset)}
        endpoints.append(item)
        if confidence == "unresolved": unresolved.append({"type": "endpoint_url", "expression": expression, "location": item["location"]})
    for match in re.finditer(r"\bfetch\s*\(", source):
        parts = _split(_balanced(source, match.end() - 1))
        if parts:
            options = parts[1] if len(parts) > 1 else ""; add("fetch", _object_value(options, "method") or "GET", parts[0], match.start(), options)
    for match in re.finditer(r"\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(", source, re.I):
        parts = _split(_balanced(source, match.end() - 1))
        if parts: add("axios", match.group(1), parts[0], match.start(), parts[2] if len(parts) > 2 else (parts[1] if len(parts) > 1 else ""))
    for match in re.finditer(r"\baxios\s*\(\s*{", source):
        data = _balanced(source, source.find("(", match.start()))
        if (url := _object_value(data, "url")): add("axios", _object_value(data, "method") or "GET", repr(url), match.start(), data)
    for match in re.finditer(r"\.open\s*\(\s*(['\"])([A-Z]+)\1\s*,", source, re.I):
        parts = _split(_balanced(source, source.find("(", match.start())))
        if len(parts) > 1: add("xmlhttprequest", match.group(2), parts[1], match.start())
    for match in re.finditer(r"(?:\$|jQuery)\s*\.\s*ajax\s*\(\s*{", source):
        data = _balanced(source, source.find("(", match.start()))
        if (url := _object_value(data, "url")): add("jquery.ajax", _object_value(data, "method") or _object_value(data, "type") or "GET", repr(url), match.start(), data)
    for pattern, kind in ((r"new\s+WebSocket\s*\(", "websocket"), (r"\bio\s*\(", "socket.io")):
        for match in re.finditer(pattern, source):
            parts = _split(_balanced(source, match.end() - 1))
            if parts:
                url, confidence, parameters = _literal(parts[0]); websockets.append({"kind": kind, "url": url, "parameters": parameters, "message_formats": [], "confidence": confidence, "location": location(match.start())})
    for pattern, framework in ((r"<Route\b[^>]*\bpath\s*=\s*(?:{\s*)?(['\"])(.*?)\1", "react-router"), (r"\bpath\s*:\s*(['\"])(.*?)\1", "router-config"), (r"RouterModule\.forRoot\s*\(", "angular")):
        for match in re.finditer(pattern, source, re.I | re.S): routes.append({"framework": framework, "path": match.group(2) if (match.lastindex or 0) >= 2 else "<route-array>", "confidence": "confirmed", "location": location(match.start())})
    auth_patterns = {"authorization_header": r"['\"]Authorization['\"]|\bAuthorization\s*:", "bearer_token": r"\bBearer\s+|['\"]Bearer['\"]\s*\+|`Bearer\s+\$\{", "auth_header": r"['\"](?:x-auth-token|x-api-key)['\"]", "token_storage": r"(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*(['\"])([^'\"]*(?:token|key|auth)[^'\"]*)\1", "auth_function": r"\b(?:login|logout|refreshToken|refresh_token)\s*[=:;(]"}
    for signal, pattern in auth_patterns.items():
        for match in re.finditer(pattern, source, re.I): auth.append({"type": signal, "value": match.group(2) if (match.lastindex or 0) >= 2 else match.group(0), "confidence": "confirmed", "location": location(match.start())})
    all_items = endpoints + websockets + routes + auth
    return {"source": source_name, "endpoints": endpoints, "websockets": websockets, "routes": routes, "authentication": auth, "confirmed": [item for item in all_items if item.get("confidence") == "confirmed"], "inferred": [item for item in all_items if item.get("confidence") == "inferred"], "unresolved": unresolved, "statistics": {"endpoints": len(endpoints), "websockets": len(websockets), "routes": len(routes), "authentication_signals": len(auth)}}

__all__ = ["extract_api"]
