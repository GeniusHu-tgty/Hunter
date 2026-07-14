"""Prioritize reconnaissance assets and attach technology attack clues."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True)
class PriorityAsset:
    """Normalized reconnaissance asset with an assigned handling priority."""

    url: str
    ip: str
    ports: tuple[int, ...]
    technologies: tuple[str, ...]
    status: int | None
    priority: str
    attack_clues: tuple[str, ...]
    reasons: tuple[str, ...]


class AssetPriority:
    """Classify reconnaissance output into P0-P3 response queues."""

    DANGEROUS_PORTS = {
        2375: "Docker API", 6379: "Redis", 9200: "Elasticsearch",
        11211: "Memcached", 27017: "MongoDB",
    }
    TECHNOLOGY_ATTACK_CLUES = {
        "PHP": ("SQLi", "LFI", "file upload", "PHP object deserialization"),
        "ASP.NET": ("MSSQL SQLi", "ViewState deserialization", "IIS short-name disclosure"),
        "Spring Boot": ("Actuator exposure", "Spring4Shell", "SpEL injection"),
        "Spring": ("Spring4Shell", "SpEL injection", "Java deserialization"),
        "Laravel": ("APP_KEY disclosure", "SQLi", "signed cookie abuse", "debug exposure"),
        "Django": ("debug page exposure", "SQLi", "signed cookie weakness", "SSTI"),
        "WordPress": ("plugin vulnerabilities", "theme vulnerabilities", "XML-RPC abuse"),
        "Flask": ("debug console", "Jinja2 SSTI", "signed session cookie weakness"),
        "FastAPI": ("OpenAPI exposure", "authorization bypass", "validation gaps"),
        "Express": ("prototype pollution", "NoSQL injection", "middleware misconfiguration"),
        "Node.js": ("prototype pollution", "command injection", "dependency vulnerabilities"),
        "Ruby on Rails": ("mass assignment", "SQLi", "secret_key_base disclosure"),
        "Java": ("Java deserialization", "JNDI injection", "XXE"),
        "Apache": ("path traversal", "request smuggling", "misconfigured modules"),
        "nginx": ("alias traversal", "request smuggling", "off-by-slash"),
        "IIS": ("short-name disclosure", "WebDAV exposure", "Windows authentication issues"),
        "Tomcat": ("manager exposure", "AJP Ghostcat", "Java deserialization"),
        "Jenkins": ("script console exposure", "unauthenticated builds", "credential disclosure"),
        "Grafana": ("authentication bypass", "plugin traversal", "dashboard secrets"),
        "Kubernetes": ("API exposure", "anonymous access", "service account token leakage"),
        "Docker": ("unauthenticated API", "container escape paths", "registry exposure"),
        "Redis": ("unauthenticated access", "file write", "Lua sandbox escape"),
        "MongoDB": ("unauthenticated access", "NoSQL injection", "database disclosure"),
        "Elasticsearch": ("unauthenticated API", "index disclosure", "script execution"),
        "MySQL": ("weak credentials", "SQLi", "FILE privilege abuse"),
        "PostgreSQL": ("weak credentials", "SQLi", "COPY command abuse"),
    }
    _P0_PATH_PATTERNS = (
        re.compile(r"(?:^|/|[-_.])\.env(?:$|/|[-_.])", re.I),
        re.compile(r"(?:^|/)\.git(?:$|/)", re.I),
        re.compile(r"(?:^|/)(?:php[-_.]?my[-_.]?admin|pma)(?:$|/)", re.I),
        re.compile(r"(?:^|/)(?:swagger(?:[-_.]?ui)?|api[-_.]?docs)(?:$|/)", re.I),
        re.compile(r"(?:^|/)actuator(?:$|/)", re.I),
    )
    _P1_PATH_PATTERN = re.compile(
        r"(?:^|/|[-_.])(?:admin|login|upload|api)(?:$|/|[-_.0-9])", re.I
    )
    _P1_TECHNOLOGIES = ("spring", "laravel", "django", "wordpress")
    _STATIC_TECHNOLOGIES = ("static", "static html", "github pages", "hugo", "jekyll")
    _STATIC_EXTENSIONS = (".html", ".htm", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg")

    def classify_asset(self, url: str, ip: str, ports: Any,
                       technologies: Any, status: Any) -> PriorityAsset:
        """Normalize reconnaissance fields and assign the strongest priority."""
        normalized_ports = self._normalize_ports(ports)
        normalized_technologies = self._normalize_technologies(technologies)
        normalized_status = self._normalize_status(status)
        path = self._normalize_path(url)
        reasons: list[str] = []

        for port in normalized_ports:
            if port in self.DANGEROUS_PORTS:
                reasons.append(f"Exposed {self.DANGEROUS_PORTS[port]} service on port {port}")
        if any(pattern.search(path) for pattern in self._P0_PATH_PATTERNS):
            reasons.append(f"Sensitive path exposed: {path or '/'}")

        if reasons:
            priority = "P0"
        else:
            if self._P1_PATH_PATTERN.search(path):
                reasons.append(f"High-value application path discovered: {path}")
            framework = next((technology for technology in normalized_technologies
                              if any(marker in technology.casefold()
                                     for marker in self._P1_TECHNOLOGIES)), None)
            if framework:
                reasons.append(f"High-value framework detected: {framework}")
            if normalized_status == 403:
                reasons.append("HTTP 403 indicates a protected or restricted surface")

            if reasons:
                priority = "P1"
            elif normalized_status in {404, 502, 503}:
                priority = "P3"
                reasons.append(f"Low-value HTTP status: {normalized_status}")
            elif self._is_static_asset(path, normalized_technologies):
                priority = "P3"
                reasons.append("Static site or static-only asset")
            else:
                priority = "P2"
                reasons.append("Live HTTP service returned 200" if normalized_status == 200
                               else "General web service requires routine review")

        attack_clues = self._attack_clues(normalized_technologies) or (
            "Content discovery", "authentication review", "input validation testing"
        )
        return PriorityAsset(
            url=str(url), ip=str(ip or ""), ports=normalized_ports,
            technologies=normalized_technologies, status=normalized_status,
            priority=priority, attack_clues=attack_clues, reasons=tuple(reasons),
        )

    def attack_surface_summary(self, assets: Iterable[PriorityAsset]) -> str:
        """Return a printable P0-P3 summary ordered by handling priority."""
        grouped = {priority: [] for priority in ("P0", "P1", "P2", "P3")}
        for asset in assets:
            grouped.setdefault(asset.priority, []).append(asset)
        lines = ["Attack Surface Summary", "=" * 22]
        for priority in ("P0", "P1", "P2", "P3"):
            priority_assets = sorted(grouped.get(priority, ()), key=lambda item: (item.url, item.ip))
            lines.extend((f"\n{priority} ({len(priority_assets)})", "-" * 8))
            if not priority_assets:
                lines.append("  No assets")
            for asset in priority_assets:
                ports = ",".join(str(port) for port in asset.ports) or "none"
                technologies = ", ".join(asset.technologies) or "unknown"
                lines.append(
                    f"  {asset.url} | IP: {asset.ip or 'unknown'} | Status: "
                    f"{asset.status if asset.status is not None else 'unknown'} | Ports: {ports} | "
                    f"Technologies: {technologies} | Reasons: {'; '.join(asset.reasons)} | "
                    f"Attack clues: {'; '.join(asset.attack_clues)}"
                )
        return "\n".join(lines)

    def _attack_clues(self, technologies: tuple[str, ...]) -> tuple[str, ...]:
        clues: list[str] = []
        for technology in technologies:
            normalized = technology.casefold()
            for known_technology, known_clues in self.TECHNOLOGY_ATTACK_CLUES.items():
                known = known_technology.casefold()
                if known in normalized or normalized in known:
                    for clue in known_clues:
                        if clue not in clues:
                            clues.append(clue)
        return tuple(clues)

    @classmethod
    def _normalize_ports(cls, ports: Any) -> tuple[int, ...]:
        discovered: set[int] = set()

        def collect(value: Any, active: bool = True) -> None:
            if value is None or isinstance(value, bool):
                return
            if isinstance(value, int):
                if active and 0 < value <= 65535:
                    discovered.add(value)
                return
            if isinstance(value, str):
                if any(marker in value.casefold() for marker in ("closed", "filtered", "down")):
                    return
                match = re.search(r"(?<!\d)(\d{1,5})(?!\d)", value)
                if match:
                    collect(int(match.group(1)), active)
                return
            if isinstance(value, Mapping):
                state = str(value.get("state", value.get("status", "open"))).casefold()
                item_active = active and not any(marker in state for marker in ("closed", "filtered", "down"))
                for key in ("port", "portid", "number", "port_number"):
                    if key in value:
                        collect(value[key], item_active)
                for key in ("ports", "open_ports", "services", "results"):
                    if key in value:
                        collect(value[key], item_active)
                for key, nested in value.items():
                    if isinstance(key, int) or (isinstance(key, str) and key.isdigit()):
                        collect(key, item_active)
                    elif isinstance(nested, (Mapping, list, tuple, set)):
                        collect(nested, item_active)
                return
            if isinstance(value, Iterable):
                for item in value:
                    collect(item, active)

        collect(ports)
        return tuple(sorted(discovered))

    @staticmethod
    def _normalize_technologies(technologies: Any) -> tuple[str, ...]:
        if technologies is None:
            return ()
        if isinstance(technologies, str):
            values = re.split(r"[,;|]", technologies)
        elif isinstance(technologies, Mapping):
            values = technologies.keys()
        else:
            try:
                values = list(technologies)
            except TypeError:
                values = [technologies]
        normalized: list[str] = []
        for value in values:
            if isinstance(value, Mapping):
                value = value.get("name", value.get("technology", value.get("product", "")))
            name = str(value).strip()
            if name and name not in normalized:
                normalized.append(name)
        return tuple(normalized)

    @staticmethod
    def _normalize_status(status: Any) -> int | None:
        if isinstance(status, bool) or status is None:
            return None
        if isinstance(status, int):
            return status if 100 <= status <= 599 else None
        match = re.search(r"(?<!\d)([1-5]\d{2})(?!\d)", str(status))
        return int(match.group(1)) if match else None

    @staticmethod
    def _normalize_path(url: str) -> str:
        text = unquote(str(url or "")).replace("\\", "/")
        parsed = urlsplit(text if "://" in text else f"//placeholder{text}")
        return re.sub(r"/{2,}", "/", parsed.path or "/").casefold()

    @classmethod
    def _is_static_asset(cls, path: str, technologies: tuple[str, ...]) -> bool:
        technology_text = " ".join(technologies).casefold()
        return (any(marker in technology_text for marker in cls._STATIC_TECHNOLOGIES)
                or path.casefold().endswith(cls._STATIC_EXTENSIONS))
