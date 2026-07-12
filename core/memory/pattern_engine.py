"""Reusable vulnerability and technology-stack pattern matching.

The engine is deliberately passive.  It classifies observations supplied by a
caller and never performs network requests or executes a recommended action.
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class _ParameterPattern:
    names: tuple[str, ...]
    vulnerability_types: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class _ResponsePattern:
    vulnerability_type: str
    expressions: tuple[str, ...]
    description: str
    confidence: float


@dataclass(frozen=True)
class _StackStrategy:
    name: str
    requirements: Mapping[str, tuple[str, ...]]
    description: str
    follow_ups: tuple[str, ...]


_PARAMETER_PATTERNS = (
    _ParameterPattern(
        ("id", "uuid", "user_id", "account_id", "order_id", "object_id"),
        ("idor",),
        "Object identifiers commonly participate in direct-object references.",
    ),
    _ParameterPattern(
        ("search", "query", "q", "keyword", "filter", "sort", "where"),
        ("sqli", "xss"),
        "Free-form query values commonly reach database or HTML sinks.",
    ),
    _ParameterPattern(
        (
            "url",
            "uri",
            "redirect",
            "redirect_url",
            "callback",
            "callback_url",
            "return",
            "return_url",
            "return_to",
            "next",
            "dest",
            "destination",
        ),
        ("ssrf", "open_redirect"),
        "URL-like parameters may control server fetches or client redirects.",
    ),
    _ParameterPattern(
        ("upload", "file", "filename", "avatar", "attachment", "import"),
        ("file_upload",),
        "File-bearing parameters commonly expose upload validation boundaries.",
    ),
    _ParameterPattern(
        ("token", "sign", "signature", "sig", "hmac", "nonce"),
        ("crypto_weakness",),
        "Signature and token parameters are candidates for cryptographic review.",
    ),
    _ParameterPattern(
        ("cmd", "command", "exec", "execute", "ping", "host"),
        ("command_injection",),
        "Command-like values may cross an operating-system execution boundary.",
    ),
    _ParameterPattern(
        ("path", "folder", "directory", "template", "page", "include"),
        ("path_traversal", "lfi"),
        "Filesystem-like values may influence local path resolution.",
    ),
)


_RESPONSE_PATTERNS = (
    _ResponsePattern(
        "sqli",
        (
            r"\bmysql_fetch(?:_array|_assoc|_row|_object)?\b",
            r"you have an error in your sql syntax",
            r"\bmysqli?_(?:query|fetch)\b",
            r"\bpg_query\(\)",
            r"\bora-\d{4,5}\b",
            r"\bsqlstate(?:\[[^\]]+\])?",
            r"unclosed quotation mark after the character string",
        ),
        "Database parser or driver error disclosed by the response.",
        0.93,
    ),
    _ResponsePattern(
        "lfi",
        (
            r"(?m)^root:[^:\r\n]*:\d+:\d+:",
            r"(?im)^\[boot loader\]",
            r"(?im)^\[operating systems\]",
            r"(?m)^\s*daemon:[^:\r\n]*:\d+:\d+:",
        ),
        "Known local operating-system file content appeared in the response.",
        0.97,
    ),
    _ResponsePattern(
        "command_injection",
        (
            r"(?m)\buid=\d+\([^)]+\)",
            r"(?m)\bgid=\d+\([^)]+\)",
            r"(?im)windows ip configuration",
            r"(?m)^[a-z0-9_.-]+\\[a-z0-9_.$-]+$",
        ),
        "Operating-system command output appeared in the response.",
        0.96,
    ),
)


_STACK_STRATEGIES = (
    _StackStrategy(
        "ASPX webshell + xp_cmdshell",
        {
            "server": ("iis", "microsoft-iis"),
            "framework": ("asp.net", "aspnet", ".net framework"),
            "database": ("sql server", "mssql", "microsoft sql server"),
        },
        "Prioritize ASP.NET deployment surfaces and SQL Server command features.",
        ("Review ASP.NET upload handlers.", "Verify SQL Server execution privileges."),
    ),
    _StackStrategy(
        "PHP webshell + UDF privilege escalation",
        {
            "server": ("apache", "httpd"),
            "framework": ("php", "laravel", "symfony", "codeigniter"),
            "database": ("mysql", "mariadb"),
        },
        "Prioritize PHP execution surfaces and MySQL UDF capability checks.",
        ("Review PHP upload and include paths.", "Verify MySQL FILE/UDF privileges."),
    ),
    _StackStrategy(
        "NoSQL injection + Node.js RCE",
        {
            "server": ("nginx",),
            "framework": ("node.js", "nodejs", "express", "nestjs", "koa"),
            "database": ("mongodb", "mongo"),
        },
        "Prioritize document-query operator injection and Node.js execution sinks.",
        ("Review JSON query operators.", "Trace child_process and template sinks."),
    ),
    _StackStrategy(
        "JSP webshell + JMX/RMI exploitation",
        {
            "server": ("tomcat", "apache tomcat"),
            "framework": ("java", "spring", "spring boot", "struts", "jsf"),
        },
        "Prioritize Java deployment surfaces and exposed management protocols.",
        ("Review WAR/JSP upload paths.", "Inventory JMX and RMI exposure."),
    ),
)


def _normalise_parameter(value: str) -> tuple[str, tuple[str, ...]]:
    raw = str(value or "").strip()
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw)
    normalised = re.sub(r"[^a-z0-9]+", "_", camel_split.lower()).strip("_")
    tokens = tuple(token for token in normalised.split("_") if token)
    return normalised, tokens


def _normalise_feature(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        value = " ".join(str(item) for item in value)
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


class PatternEngine:
    """Match reusable vulnerability signals and stack recommendations."""

    def __init__(
        self,
        parameter_patterns: Iterable[_ParameterPattern] | None = None,
        response_patterns: Iterable[_ResponsePattern] | None = None,
        stack_strategies: Iterable[_StackStrategy] | None = None,
    ) -> None:
        self._parameter_patterns = tuple(parameter_patterns or _PARAMETER_PATTERNS)
        self._response_patterns = tuple(response_patterns or _RESPONSE_PATTERNS)
        self._stack_strategies = tuple(stack_strategies or _STACK_STRATEGIES)

    def match_parameter(self, parameter: str, context: str = "") -> dict[str, Any]:
        """Return likely vulnerability classes for a parameter name."""

        normalised, tokens = _normalise_parameter(parameter)
        context_normalised = _normalise_feature(context)
        matches: list[dict[str, Any]] = []

        for pattern in self._parameter_patterns:
            exact_names = set(pattern.names)
            exact = normalised in exact_names
            token_hits = [token for token in tokens if token in exact_names]
            compound_hits = [
                name
                for name in pattern.names
                if "_" in name and (normalised == name or normalised.endswith(f"_{name}"))
            ]
            if not (exact or token_hits or compound_hits):
                continue

            matched_names = _unique(
                ([normalised] if exact else []) + token_hits + compound_hits
            )
            base_confidence = 0.9 if exact else 0.72
            if compound_hits:
                base_confidence = max(base_confidence, 0.84)
            context_boost = 0.0
            if context_normalised:
                related_terms = set(tokens) | {
                    vuln.replace("_", " ")
                    for vuln in pattern.vulnerability_types
                }
                if any(term and term in context_normalised for term in related_terms):
                    context_boost = 0.05
            matches.append(
                {
                    "matched_names": matched_names,
                    "vulnerability_types": list(pattern.vulnerability_types),
                    "confidence": round(min(0.99, base_confidence + context_boost), 2),
                    "description": pattern.description,
                }
            )

        vulnerability_types = _unique(
            vulnerability
            for match in matches
            for vulnerability in match["vulnerability_types"]
        )
        confidence = max((match["confidence"] for match in matches), default=0.0)
        evidence = [
            {
                "type": "parameter-name",
                "matched": match["matched_names"],
                "description": match["description"],
            }
            for match in matches
        ]
        return {
            "parameter": str(parameter or ""),
            "normalized_parameter": normalised,
            "context": str(context or ""),
            "vulnerability_types": vulnerability_types,
            "confidence": confidence,
            "evidence": evidence,
            "matches": deepcopy(matches),
        }

    def match_response(self, response: Any) -> dict[str, Any]:
        """Classify response text using confirmation-grade passive signatures."""

        text = self._response_text(response)
        matches: list[dict[str, Any]] = []
        for pattern in self._response_patterns:
            evidence = []
            for expression in pattern.expressions:
                match = re.search(expression, text)
                if match:
                    evidence.append(
                        {
                            "type": "response-pattern",
                            "pattern": expression,
                            "matched": match.group(0)[:160],
                        }
                    )
            if evidence:
                confidence = min(0.99, pattern.confidence + 0.02 * (len(evidence) - 1))
                matches.append(
                    {
                        "vulnerability_type": pattern.vulnerability_type,
                        "confidence": round(confidence, 2),
                        "description": pattern.description,
                        "evidence": evidence,
                    }
                )

        matches.sort(key=lambda item: (-item["confidence"], item["vulnerability_type"]))
        if not matches:
            return {
                "vulnerability_type": None,
                "confidence": 0.0,
                "evidence": [],
                "matches": [],
            }

        primary = matches[0]
        return {
            "vulnerability_type": primary["vulnerability_type"],
            "confidence": primary["confidence"],
            "evidence": deepcopy(primary["evidence"]),
            "matches": matches,
        }

    def recommend_stack(self, features: Mapping[str, Any] | None) -> dict[str, Any]:
        """Recommend a strategy from passive technology-stack features."""

        supplied = dict(features or {})
        normalised = {
            "server": _normalise_feature(
                supplied.get("server") or supplied.get("web_server")
            ),
            "framework": _normalise_feature(
                supplied.get("framework")
                or supplied.get("language")
                or supplied.get("runtime")
            ),
            "database": _normalise_feature(
                supplied.get("database") or supplied.get("db")
            ),
        }
        ranked: list[dict[str, Any]] = []

        for strategy in self._stack_strategies:
            matched_features: dict[str, str] = {}
            missing_features: list[str] = []
            for feature, expected_values in strategy.requirements.items():
                actual = normalised.get(feature, "")
                matched = next(
                    (
                        expected
                        for expected in expected_values
                        if expected in actual or actual in expected
                    ),
                    None,
                )
                if actual and matched:
                    matched_features[feature] = matched
                else:
                    missing_features.append(feature)

            total = len(strategy.requirements)
            matched_count = len(matched_features)
            if not matched_count:
                continue
            coverage = matched_count / total
            confidence = min(0.98, 0.25 + coverage * 0.7)
            ranked.append(
                {
                    "name": strategy.name,
                    "description": strategy.description,
                    "follow_ups": list(strategy.follow_ups),
                    "matched_features": matched_features,
                    "missing_features": missing_features,
                    "confidence": round(confidence, 2),
                }
            )

        ranked.sort(
            key=lambda item: (
                -item["confidence"],
                len(item["missing_features"]),
                item["name"],
            )
        )
        if not ranked:
            return {
                "primary": None,
                "alternatives": [],
                "confidence": 0.0,
                "evidence": [],
                "observed_stack": normalised,
            }

        primary = ranked[0]
        evidence = [
            {
                "type": "stack-feature",
                "feature": feature,
                "observed": normalised[feature],
                "matched": matched,
            }
            for feature, matched in primary["matched_features"].items()
        ]
        return {
            "primary": primary,
            "alternatives": ranked[1:],
            "confidence": primary["confidence"],
            "evidence": evidence,
            "observed_stack": normalised,
        }

    @staticmethod
    def _response_text(response: Any) -> str:
        if isinstance(response, bytes):
            return response.decode("utf-8", errors="replace")
        if isinstance(response, str):
            return response
        if isinstance(response, Mapping):
            for key in ("body", "text", "content", "response"):
                if key in response:
                    return PatternEngine._response_text(response[key])
            return str(response)
        for attribute in ("text", "body", "content"):
            if hasattr(response, attribute):
                return PatternEngine._response_text(getattr(response, attribute))
        return str(response or "")


__all__ = ["PatternEngine"]
