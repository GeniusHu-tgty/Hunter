from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from html.parser import HTMLParser
from typing import Any, TypedDict


_SENSITIVE_NAMES = {"token", "secret", "password", "passwd", "authorization", "cookie", "api_key", "apikey"}
_WORD = re.compile(r"[A-Za-z0-9_]+")


class ResponseProjection(TypedDict, total=False):
    """Normalized response metadata persisted by the request broker."""

    status_code: int
    url: str
    redirect_count: int
    headers: dict[str, str]
    cookies: list[str]
    body_hash: str
    body_length: int
    body_sample: str
    title: str
    html: dict[str, Any]
    json: dict[str, Any]


class _HtmlFeatures(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: Counter[str] = Counter()
        self.forms: list[str] = []
        self.links: list[str] = []
        self.script_count = 0
        self._hidden_depth = 0
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags[tag] += 1
        values = dict(attrs)
        if tag in {"script", "style"}:
            self._hidden_depth += 1
        if tag == "script":
            self.script_count += 1
        if tag == "form" and values.get("action"):
            self.forms.append(values["action"])
        if tag in {"a", "link"} and values.get("href"):
            self.links.append(values["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden_depth:
            self.text.append(data)


def _simhash(text: str) -> str:
    weights = [0] * 64
    for word in _WORD.findall(text.lower()):
        digest = int.from_bytes(hashlib.sha256(word.encode("utf-8")).digest()[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if digest & (1 << bit) else -1
    value = sum(1 << bit for bit, weight in enumerate(weights) if weight >= 0)
    return f"{value:016x}"


def _json_features(value: Any) -> dict[str, Any]:
    paths: list[str] = []
    sensitive: list[str] = []

    def visit(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key in sorted(item):
                next_path = f"{path}.{key}" if path else str(key)
                paths.append(next_path)
                if str(key).lower() in _SENSITIVE_NAMES:
                    sensitive.append(next_path)
                visit(item[key], next_path)
        elif isinstance(item, list):
            for child in item:
                visit(child, f"{path}[]")

    visit(value, "")
    top_level_type = "object" if isinstance(value, dict) else "array" if isinstance(value, list) else type(value).__name__
    business_code = next((value[key] for key in ("code", "status", "error_code") if isinstance(value, dict) and key in value), None)
    structure = json.dumps(_shape(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "top_level_type": top_level_type,
        "business_code": business_code,
        "key_paths": paths,
        "sensitive_fields": sensitive,
        "structure_hash": hashlib.sha256(structure.encode("utf-8")).hexdigest(),
    }


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_shape(value[0])] if value else []
    return type(value).__name__


def _simhash_similarity(left: str, right: str) -> float:
    distance = (int(left, 16) ^ int(right, 16)).bit_count()
    return 1.0 - distance / 64.0


def block_cluster_similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    """Compare HTML response projections using the configured WAF-cluster weights."""
    first = left.get("html") or {}
    second = right.get("html") or {}
    if not first or not second:
        return 0.0
    title = float(first.get("title") == second.get("title"))
    tags = set(first.get("dom_histogram", {})) | set(second.get("dom_histogram", {}))
    dom = (sum(min(first["dom_histogram"].get(tag, 0), second["dom_histogram"].get(tag, 0)) for tag in tags) /
           max(1, sum(max(first["dom_histogram"].get(tag, 0), second["dom_histogram"].get(tag, 0)) for tag in tags)))
    text = _simhash_similarity(str(first.get("visible_text_simhash", "0")), str(second.get("visible_text_simhash", "0")))
    length = 1.0 - min(1.0, abs(int(first.get("length_bucket", 0)) - int(second.get("length_bucket", 0))) / 1024.0)
    headers = float(left.get("headers") == right.get("headers"))
    route_form = float(first.get("forms") == second.get("forms"))
    return round(title * 0.15 + dom * 0.25 + text * 0.30 + length * 0.10 + headers * 0.10 + route_form * 0.10, 4)


def build_response_projection(response: Any) -> ResponseProjection:
    text = str(getattr(response, "text", "") or "")
    headers = {str(key).lower(): str(value) for key, value in dict(getattr(response, "headers", {}) or {}).items()}
    result: ResponseProjection = {
        "status_code": int(getattr(response, "status_code", 0) or 0),
        "url": str(getattr(response, "url", "") or ""),
        "redirect_count": len(getattr(response, "history", ()) or ()),
        "headers": headers,
        "cookies": sorted(str(key) for key in dict(getattr(response, "cookies", {}) or {})),
        "body_hash": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
        "body_length": len(text),
        "body_sample": text[:1024],
    }
    content_type = headers.get("content-type", "").lower()
    if "json" in content_type:
        try:
            result["json"] = _json_features(json.loads(text))
        except json.JSONDecodeError:
            result["json"] = {"invalid": True}
    else:
        parser = _HtmlFeatures()
        parser.feed(text)
        visible = " ".join(" ".join(parser.text).split())
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        result["title"] = title_match.group(1).strip()[:160] if title_match else ""
        result["html"] = {
            "title": result["title"], "visible_text_simhash": _simhash(visible),
            "dom_histogram": dict(sorted(parser.tags.items())), "forms": sorted(set(parser.forms)),
            "script_count": parser.script_count, "links": sorted(set(parser.links)),
            "length_bucket": (len(text) // 256) * 256,
        }
    return result
