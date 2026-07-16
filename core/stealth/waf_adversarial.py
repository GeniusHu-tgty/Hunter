"""Bounded WAF profiling, strategy search, and backend-proof verification."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from .waf_detector import BLOCK_WORDS, WAFDetector


_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}
_SENSITIVE_FIELD_RE = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|pass(?:word)?|secret|session|token)",
    re.I,
)
_CHALLENGE_MARKERS = (
    "attention required",
    "checking your browser",
    "enable javascript and cookies",
    "just a moment",
    "managed challenge",
    "verify you are human",
)
_UNSET = object()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _redact_value(value: Any, key: str = "") -> Any:
    if key and _SENSITIVE_FIELD_RE.search(str(key)):
        return "REDACTED"
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact_value(item, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    return value


def _redact_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(name): "REDACTED"
        if str(name).casefold() in _SENSITIVE_HEADERS
        else value
        for name, value in headers.items()
    }


def _redact_text(value: str, limit: int = 800) -> str:
    text = str(value or "")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        redacted = re.sub(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
            "Bearer REDACTED",
            text,
        )
        redacted = re.sub(
            r"(?i)\b(?:token|secret|password|session|cookie)\s*[:=]\s*[^\s,;]+",
            lambda match: match.group(0).split(match.group(0)[len(match.group(0).split()[0]):], 1)[0]
            if False
            else re.sub(r"[:=].*", ": REDACTED", match.group(0)),
            redacted,
        )
        return redacted[:limit]
    return json.dumps(
        _redact_value(parsed),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )[:limit]


@dataclass
class HTTPRequestTemplate:
    method: str
    url: str
    headers: dict[str, Any] = field(default_factory=dict)
    body: Any = None

    def __post_init__(self) -> None:
        self.method = str(self.method or "GET").upper()
        self.url = str(self.url or "").strip()
        if not self.url:
            raise ValueError("request URL must not be empty")
        self.headers = copy.deepcopy(dict(self.headers or {}))
        self.body = copy.deepcopy(self.body)

    def digest(self) -> str:
        canonical = json.dumps(
            {
                "method": self.method,
                "url": self.url,
                "headers": self.headers,
                "body": self.body,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return _sha256_text(canonical)

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        headers = _redact_headers(self.headers) if redact else copy.deepcopy(self.headers)
        body = _redact_value(self.body) if redact else copy.deepcopy(self.body)
        return {
            "method": self.method,
            "url": self.url,
            "headers": headers,
            "body": body,
            "request_digest": self.digest(),
        }


@dataclass
class HTTPObservation:
    status_code: int
    body: str = ""
    headers: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str = ""
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.status_code = int(self.status_code or 0)
        self.body = str(self.body or "")
        self.headers = copy.deepcopy(dict(self.headers or {}))
        self.elapsed_ms = max(0.0, float(self.elapsed_ms or 0.0))
        self.error = str(self.error or "")
        self.timeline = copy.deepcopy(list(self.timeline or []))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "HTTPObservation":
        timeline = list(value.get("timeline") or [])
        elapsed_ms = float(value.get("elapsed_ms") or 0.0)
        if not elapsed_ms and timeline:
            elapsed = next(
                (
                    item.get("elapsed")
                    for item in reversed(timeline)
                    if isinstance(item, Mapping) and item.get("elapsed") is not None
                ),
                0.0,
            )
            elapsed_ms = float(elapsed or 0.0) * 1000.0
        return cls(
            status_code=int(value.get("status_code") or 0),
            body=str(value.get("body") or ""),
            headers=dict(value.get("headers") or {}),
            elapsed_ms=elapsed_ms,
            error=str(value.get("error") or ""),
            timeline=timeline,
        )

    def evidence_summary(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": _redact_headers(self.headers),
            "body_sha256": _sha256_text(self.body),
            "body_excerpt": _redact_text(self.body),
            "body_length": len(self.body),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "error": _redact_text(self.error, limit=300),
        }


@dataclass(frozen=True)
class OracleResult:
    confirmed: bool
    signal: str = ""
    reason: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": bool(self.confirmed),
            "signal": str(self.signal),
            "reason": str(self.reason),
            "details": _redact_value(dict(self.details)),
        }


class ResponseOracle:
    """Confirm origin behavior from a response marker or JSON pointer."""

    def __init__(
        self,
        *,
        body_marker: str = "",
        json_pointer: str = "",
        expected: Any = _UNSET,
        baseline_body: str = "",
        status_codes: Sequence[int] | None = None,
    ) -> None:
        self.body_marker = str(body_marker or "")
        self.json_pointer = str(json_pointer or "")
        self.expected = expected
        self.baseline_body = str(baseline_body or "")
        self.status_codes = {
            int(status)
            for status in (status_codes or tuple(range(200, 300)))
        }
        if not self.body_marker and not self.json_pointer:
            raise ValueError("response oracle requires a body marker or JSON pointer")

    @staticmethod
    def _pointer(body: str, pointer: str) -> Any:
        value = json.loads(body)
        if pointer in ("", "/"):
            return value
        for raw_part in pointer.lstrip("/").split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                value = value[int(part)]
            else:
                value = value[part]
        return value

    def __call__(
        self,
        _request: HTTPRequestTemplate,
        observation: HTTPObservation,
    ) -> OracleResult:
        if observation.status_code not in self.status_codes:
            return OracleResult(False, reason="response status did not satisfy the oracle")
        if self.body_marker:
            if self.body_marker in self.baseline_body:
                return OracleResult(
                    False,
                    reason="oracle signal already existed in baseline",
                )
            if self.body_marker in observation.body:
                return OracleResult(
                    True,
                    signal="body_marker",
                    details={"marker_sha256": _sha256_text(self.body_marker)},
                )
            return OracleResult(False, reason="body marker was not observed")
        try:
            actual = self._pointer(observation.body, self.json_pointer)
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return OracleResult(False, reason="JSON pointer could not be resolved")
        if self.expected is not _UNSET and actual != self.expected:
            return OracleResult(False, reason="JSON pointer value did not match")
        if self.baseline_body:
            try:
                baseline_value = self._pointer(self.baseline_body, self.json_pointer)
            except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
                baseline_value = _UNSET
            if baseline_value is not _UNSET and baseline_value == actual:
                return OracleResult(
                    False,
                    reason="oracle signal already existed in baseline",
                )
        return OracleResult(
            True,
            signal="json_pointer_match",
            details={"json_pointer": self.json_pointer, "value": actual},
        )


@dataclass(frozen=True)
class SearchBudget:
    max_requests: int = 12
    repetitions: int = 3
    max_consecutive_blocks: int = 4

    def __post_init__(self) -> None:
        if int(self.max_requests) < 1:
            raise ValueError("max_requests must be at least 1")
        if int(self.repetitions) < 1:
            raise ValueError("repetitions must be at least 1")
        if int(self.max_consecutive_blocks) < 1:
            raise ValueError("max_consecutive_blocks must be at least 1")


@dataclass
class WAFProfile:
    gate: str
    waf_type: str | None
    confidence: float
    baseline: dict[str, Any]
    blocked: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "waf_type": self.waf_type,
            "confidence": round(float(self.confidence), 3),
            "baseline": copy.deepcopy(self.baseline),
            "blocked": copy.deepcopy(self.blocked),
        }


@dataclass
class WAFSearchResult:
    verdict: str
    verified: bool
    bypass_found: bool
    strategy_id: str
    reproduction_count: int
    requests_used: int
    stop_reason: str
    outcomes: list[dict[str, Any]]
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "verified": self.verified,
            "bypass_found": self.bypass_found,
            "strategy_id": self.strategy_id,
            "reproduction_count": self.reproduction_count,
            "requests_used": self.requests_used,
            "stop_reason": self.stop_reason,
            "outcomes": copy.deepcopy(self.outcomes),
            "evidence": copy.deepcopy(self.evidence),
        }


class _ResponseAdapter:
    def __init__(self, observation: HTTPObservation) -> None:
        self.status_code = observation.status_code
        self.text = observation.body
        self.headers = observation.headers


class StealthWAFExecutor:
    """Execute exactly one explicit strategy through StealthHTTPClient."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def __call__(
        self,
        request: HTTPRequestTemplate,
        strategy_id: str | None = None,
    ) -> HTTPObservation:
        options: dict[str, Any] = {
            "max_retries": 0,
            "follow_redirects": False,
            "max_body_chars": 16000,
        }
        if strategy_id:
            options["initial_strategy"] = {
                "id": str(strategy_id),
                "description": "explicit adversarial search candidate",
            }
        result = self.client.stealth_request(
            request.method,
            request.url,
            headers=copy.deepcopy(request.headers),
            data=copy.deepcopy(request.body),
            options=options,
        )
        return HTTPObservation.from_mapping(result)


class WAFAdversarialEngine:
    """Profile a gate and search existing Hunter strategies under a hard budget."""

    def __init__(
        self,
        executor: Callable[[HTTPRequestTemplate, str | None], HTTPObservation | Mapping[str, Any]],
        detector: WAFDetector | None = None,
    ) -> None:
        self.executor = executor
        self.detector = detector or WAFDetector()

    def _execute(
        self,
        request: HTTPRequestTemplate,
        strategy_id: str | None,
    ) -> HTTPObservation:
        value = self.executor(request, strategy_id)
        if isinstance(value, HTTPObservation):
            return value
        if isinstance(value, Mapping):
            return HTTPObservation.from_mapping(value)
        raise TypeError("WAF executor must return HTTPObservation or a mapping")

    def classify(self, observation: HTTPObservation) -> dict[str, Any]:
        body_lower = observation.body.casefold()
        headers_lower = {
            str(key).casefold(): str(value).casefold()
            for key, value in observation.headers.items()
        }
        detection = self.detector.detect_response(_ResponseAdapter(observation))
        if observation.error or observation.status_code == 0:
            classification = "transport_error"
        elif observation.status_code == 429:
            classification = "rate_limit"
        elif (
            any(marker in body_lower for marker in _CHALLENGE_MARKERS)
            or "cf-mitigated" in headers_lower
        ):
            classification = "challenge"
        elif 200 <= observation.status_code < 300 and any(
            marker.casefold() in body_lower for marker in BLOCK_WORDS
        ):
            classification = "soft_block"
        elif detection.get("blocked"):
            classification = "signature"
        elif observation.status_code >= 500:
            classification = "upstream_error"
        elif 200 <= observation.status_code < 400:
            classification = "pass"
        else:
            classification = "application_denial"
        return {
            "classification": classification,
            "status_code": observation.status_code,
            "blocked": classification in {
                "challenge",
                "rate_limit",
                "signature",
                "soft_block",
            },
            "waf_type": detection.get("waf_type"),
            "confidence": float(detection.get("confidence") or 0.0),
            "body_sha256": _sha256_text(observation.body),
        }

    def profile(
        self,
        baseline_request: HTTPRequestTemplate,
        blocked_request: HTTPRequestTemplate,
    ) -> WAFProfile:
        baseline_observation = self._execute(baseline_request, None)
        blocked_observation = self._execute(blocked_request, None)
        baseline = self.classify(baseline_observation)
        blocked = self.classify(blocked_observation)
        if baseline["classification"] in {"challenge", "rate_limit"}:
            gate = baseline["classification"]
        elif baseline["classification"] != "pass":
            gate = "session_or_fingerprint"
        elif blocked["classification"] in {
            "challenge",
            "rate_limit",
            "signature",
            "soft_block",
        }:
            gate = blocked["classification"]
        else:
            gate = "no_gate_observed"
        return WAFProfile(
            gate=gate,
            waf_type=blocked.get("waf_type") or baseline.get("waf_type"),
            confidence=max(
                float(baseline.get("confidence") or 0.0),
                float(blocked.get("confidence") or 0.0),
            ),
            baseline=baseline,
            blocked=blocked,
        )

    @staticmethod
    def _unique_strategies(strategy_ids: Sequence[str]) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        for value in strategy_ids:
            strategy_id = str(value or "").strip()
            if strategy_id and strategy_id not in seen:
                output.append(strategy_id)
                seen.add(strategy_id)
        return output

    def _evidence(
        self,
        request: HTTPRequestTemplate,
        profile: WAFProfile,
        strategy_id: str,
        reproduction_count: int,
        observations: Sequence[HTTPObservation],
    ) -> dict[str, Any]:
        return {
            "request": request.to_dict(redact=True),
            "profile": profile.to_dict(),
            "strategy_id": strategy_id,
            "reproduction_count": reproduction_count,
            "observations": [item.evidence_summary() for item in observations],
        }

    def search(
        self,
        request: HTTPRequestTemplate,
        *,
        profile: WAFProfile,
        oracle: Callable[[HTTPRequestTemplate, HTTPObservation], OracleResult],
        budget: SearchBudget | None = None,
        strategy_ids: Sequence[str] | None = None,
    ) -> WAFSearchResult:
        budget = budget or SearchBudget()
        selected = self._unique_strategies(
            strategy_ids
            if strategy_ids is not None
            else [
                item["id"]
                for item in self.detector.strategies_for(
                    profile.waf_type or "custom/unknown"
                )
            ]
        )
        requests_used = 0
        consecutive_blocks = 0
        bypass_found = False
        outcomes: list[dict[str, Any]] = []
        best_strategy = ""
        best_reproductions = 0
        best_observations: list[HTTPObservation] = []
        stop_reason = "strategies_exhausted"

        for strategy_id in selected:
            if requests_used >= budget.max_requests:
                stop_reason = "request_budget_exhausted"
                break
            first = self._execute(request, strategy_id)
            requests_used += 1
            classification = self.classify(first)
            transport_passed = classification["classification"] == "pass"
            outcome: dict[str, Any] = {
                "strategy_id": strategy_id,
                "classification": classification["classification"],
                "transport_passed": transport_passed,
                "oracle_confirmed": False,
                "reproduction_count": 0,
                "observation": first.evidence_summary(),
            }
            if not transport_passed:
                if classification["blocked"]:
                    consecutive_blocks += 1
                else:
                    consecutive_blocks = 0
                outcomes.append(outcome)
                if consecutive_blocks >= budget.max_consecutive_blocks:
                    stop_reason = "consecutive_block_limit"
                    break
                continue

            consecutive_blocks = 0
            bypass_found = True
            oracle_result = oracle(request, first)
            outcome["oracle"] = oracle_result.to_dict()
            outcome["oracle_confirmed"] = oracle_result.confirmed
            reproductions = 1 if oracle_result.confirmed else 0
            candidate_observations = [first]

            while (
                oracle_result.confirmed
                and reproductions < budget.repetitions
                and requests_used < budget.max_requests
            ):
                repeated = self._execute(request, strategy_id)
                requests_used += 1
                candidate_observations.append(repeated)
                repeat_classification = self.classify(repeated)
                if repeat_classification["classification"] != "pass":
                    break
                oracle_result = oracle(request, repeated)
                if not oracle_result.confirmed:
                    break
                reproductions += 1

            outcome["reproduction_count"] = reproductions
            outcome["observations"] = [
                item.evidence_summary() for item in candidate_observations
            ]
            outcomes.append(outcome)
            if reproductions > best_reproductions:
                best_strategy = strategy_id
                best_reproductions = reproductions
                best_observations = candidate_observations
            if reproductions >= budget.repetitions:
                evidence = self._evidence(
                    request,
                    profile,
                    strategy_id,
                    reproductions,
                    candidate_observations,
                )
                return WAFSearchResult(
                    verdict="verified",
                    verified=True,
                    bypass_found=True,
                    strategy_id=strategy_id,
                    reproduction_count=reproductions,
                    requests_used=requests_used,
                    stop_reason="verified",
                    outcomes=outcomes,
                    evidence=evidence,
                )
            if requests_used >= budget.max_requests:
                stop_reason = "request_budget_exhausted"
                break

        verdict = "likely" if best_reproductions else "inconclusive"
        return WAFSearchResult(
            verdict=verdict,
            verified=False,
            bypass_found=bypass_found,
            strategy_id=best_strategy,
            reproduction_count=best_reproductions,
            requests_used=requests_used,
            stop_reason=stop_reason,
            outcomes=outcomes,
            evidence=self._evidence(
                request,
                profile,
                best_strategy,
                best_reproductions,
                best_observations,
            ),
        )


__all__ = [
    "HTTPObservation",
    "HTTPRequestTemplate",
    "OracleResult",
    "ResponseOracle",
    "SearchBudget",
    "StealthWAFExecutor",
    "WAFAdversarialEngine",
    "WAFProfile",
    "WAFSearchResult",
]
