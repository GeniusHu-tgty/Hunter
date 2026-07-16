from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_RISK_MARKERS = {
    "admin": ("admin", "manage"),
    "export": ("export", "download"),
    "upload": ("upload", "import"),
    "callback": ("callback", "webhook", "redirect"),
    "auth": ("login", "oauth", "token", "auth"),
    "graphql": ("graphql",),
    "websocket": ("ws", "socket"),
    "object_id": ("/users/", "/user/", "/orders/", "/items/", "/api/"),
}


def _canonical_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _risk_categories(url: str, parameters: list[str]) -> list[str]:
    signal = f"{url.lower()} {' '.join(parameters).lower()}"
    return [name for name, markers in _RISK_MARKERS.items() if any(marker in signal for marker in markers)]


def build_attack_list(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize passive endpoint observations into an ordered discovery queue."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for observation in observations:
        url = _canonical_url(str(observation.get("url", "")))
        method = str(observation.get("method", "GET")).upper()
        if not url or not urlsplit(url).scheme or not urlsplit(url).netloc:
            continue
        key = (method, url)
        entry = merged.setdefault(key, {"url": url, "method": method, "sources": set(), "parameters": set(), "auth_hints": set()})
        entry["sources"].add(str(observation.get("source", "unknown")))
        entry["parameters"].update(str(value) for value in observation.get("parameters", []) if value)
        if observation.get("auth"):
            entry["auth_hints"].add(str(observation["auth"]))

    result = []
    for entry in merged.values():
        parameters = sorted(entry["parameters"])
        categories = _risk_categories(entry["url"], parameters)
        result.append({
            "url": entry["url"], "method": entry["method"], "sources": sorted(entry["sources"]),
            "parameters": parameters, "auth_hints": sorted(entry["auth_hints"]),
            "risk_categories": categories,
            "recommended_next": "broker_probe" if categories else "discover_review",
        })
    return sorted(result, key=lambda item: (-len(item["risk_categories"]), item["url"], item["method"]))
