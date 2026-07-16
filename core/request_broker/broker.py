from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit, urlunsplit

from .artifacts import ArtifactStore
from .identity import IdentityPool
from .projection import block_cluster_similarity, build_response_projection


class Classification(str, Enum):
    ALLOWED_APP = "ALLOWED_APP"
    WAF_BLOCK = "WAF_BLOCK"
    CAPTCHA = "CAPTCHA"
    RATE_LIMITED = "RATE_LIMITED"
    SOFT_BAN = "SOFT_BAN"
    LOGIN_REDIRECT = "LOGIN_REDIRECT"


class BrokerTransport(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] | None = None
    data: Any = None
    json: Any = None
    timeout: float = 15.0
    mode: str = "discover"
    identity: str = "anonymous"


@dataclass
class BrokerOutcome:
    classification: Classification
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    missing_inputs: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    projection: dict[str, Any] = field(default_factory=dict)


_WAF_WORDS = (
    "access denied",
    "request blocked",
    "security policy",
    "web application firewall",
    "attention required",
    "temporarily blocked",
    "被拦截",
    "安全验证",
)
_CAPTCHA_WORDS = ("captcha", "recaptcha", "hcaptcha", "verify you are human", "人机验证")
_LOGIN_WORDS = ("sign in", "log in", "登录", "统一身份认证", "cas/login")
_WAF_HEADERS = ("cf-ray", "x-sucuri-id", "x-waf", "x-cdn", "server: cloudflare")


class LegacyRequestsAdapter:
    """Requests-compatible facade used by legacy Hunter scanners."""

    def __init__(self, broker: "RequestBroker", identity: str = "anonymous") -> None:
        self.broker = broker
        self.identity = identity
        self.headers: dict[str, str] = {}

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        headers = dict(self.headers)
        headers.update(kwargs.pop("headers", {}) or {})
        spec = RequestSpec(
            method=method,
            url=url,
            headers=headers,
            params=kwargs.pop("params", None),
            data=kwargs.pop("data", None),
            json=kwargs.pop("json", None),
            timeout=float(kwargs.pop("timeout", 15.0)),
            identity=self.identity,
        )
        return self.broker.raw_request(spec, **kwargs)

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)


class RequestBroker:
    """Classifies every response and persists per-origin WAF cooldown state."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        transport: BrokerTransport | None = None,
        now: Callable[[], float] = time.time,
        max_cooldown_seconds: float = 600.0,
        hard_block_threshold: int = 5,
        artifact_quota_bytes: int = 500 * 1024 * 1024,
        identity_pool: IdentityPool | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.now = now
        self.max_cooldown_seconds = max_cooldown_seconds
        self.hard_block_threshold = max(1, int(hard_block_threshold))
        self.transport = transport or self._default_transport()
        self.identity_pool = identity_pool or IdentityPool()
        self.artifacts = ArtifactStore(self.state_dir / "artifacts", quota_bytes=artifact_quota_bytes)
        self.db = sqlite3.connect(self.state_dir / "state.sqlite")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS origin_state (
            state_key TEXT PRIMARY KEY, state TEXT NOT NULL, cooldown_until REAL NOT NULL,
            block_count INTEGER NOT NULL, last_classification TEXT NOT NULL,
            healthy_projection TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(origin_state)")}
        if "current_proxy" not in columns:
            self.db.execute("ALTER TABLE origin_state ADD COLUMN current_proxy TEXT NOT NULL DEFAULT ''")
        if "work_cursor" not in columns:
            self.db.execute("ALTER TABLE origin_state ADD COLUMN work_cursor TEXT NOT NULL DEFAULT '{}'")
        self.db.commit()

    @staticmethod
    def _default_transport() -> BrokerTransport:
        from core.stealth.stealth_http_client import StealthHTTPClient

        class StealthBrokerTransport:
            def __init__(self) -> None:
                self.client = StealthHTTPClient(state_dir="sessions/stealth")
                self.sessions: dict[str, Any] = {}

            def request(self, method: str, url: str, **kwargs: Any) -> Any:
                origin = RequestBroker._origin(url)
                session = self.sessions.get(origin)
                if session is None:
                    state = self.client.session_create(origin)
                    session = self.client.detection_session(state["session_id"])
                    self.sessions[origin] = session
                return session.request(method, url, **kwargs)

        return StealthBrokerTransport()

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def _state_key(self, url: str, identity: str = "anonymous") -> str:
        return f"{self._origin(url)}|{identity}"

    @staticmethod
    def _response_text(response: Any) -> str:
        return str(getattr(response, "text", "") or "")

    def _projection(self, response: Any) -> dict[str, Any]:
        return build_response_projection(response)

    def classify_response(self, spec: RequestSpec, response: Any) -> BrokerOutcome:
        projection = self._projection(response)
        status = projection["status_code"]
        text = projection["body_sample"].lower()
        headers = projection["headers"]
        header_text = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
        if status == 429:
            return BrokerOutcome(Classification.RATE_LIMITED, 1.0, next_actions=["cool_down_target"], projection=projection)
        if any(word in text for word in _CAPTCHA_WORDS):
            return BrokerOutcome(Classification.CAPTCHA, 0.98, next_actions=["open_browser_challenge"], projection=projection)
        if any(word in text for word in _WAF_WORDS) or any(marker in header_text for marker in _WAF_HEADERS):
            return BrokerOutcome(Classification.WAF_BLOCK, 0.95, next_actions=["cool_down_target"], projection=projection)
        final_url = projection["url"].lower()
        if status in {301, 302, 303, 307, 308} or any(word in final_url for word in ("/login", "/cas/")):
            return BrokerOutcome(Classification.LOGIN_REDIRECT, 0.9, next_actions=["provide_identity"], projection=projection)
        if status == 200 and projection["body_length"] < 32:
            return BrokerOutcome(Classification.SOFT_BAN, 0.7, next_actions=["cool_down_target"], projection=projection)
        return BrokerOutcome(Classification.ALLOWED_APP, 0.8, projection=projection)

    def _record(self, url: str, identity: str, outcome: BrokerOutcome) -> None:
        key = self._state_key(url, identity)
        old = self.state_for(url, identity)
        block = outcome.classification in {Classification.WAF_BLOCK, Classification.RATE_LIMITED, Classification.SOFT_BAN, Classification.CAPTCHA}
        block_count = int(old["block_count"]) + 1 if block else 0
        cooldown = 0.0
        state = "HEALTHY"
        if block:
            cooldown = self.now() + min(30.0 * (2 ** max(0, block_count - 1)), self.max_cooldown_seconds)
            state = "COOLING_DOWN"
            if block_count >= self.hard_block_threshold:
                state = "HARD_BLOCKED"
        healthy = old["healthy_projection"]
        if outcome.classification is Classification.ALLOWED_APP:
            healthy = outcome.projection
        self.db.execute(
            """INSERT INTO origin_state(state_key,state,cooldown_until,block_count,last_classification,healthy_projection)
            VALUES(?,?,?,?,?,?) ON CONFLICT(state_key) DO UPDATE SET
            state=excluded.state,cooldown_until=excluded.cooldown_until,block_count=excluded.block_count,
            last_classification=excluded.last_classification,healthy_projection=excluded.healthy_projection""",
            (key, state, cooldown, block_count, outcome.classification.value, json.dumps(healthy, sort_keys=True)),
        )
        self.db.commit()

    @staticmethod
    def _matches_healthy_baseline(current: dict[str, Any], baseline: dict[str, Any]) -> bool:
        if current.get("status_code") != baseline.get("status_code"):
            return False
        current_html = current.get("html") or {}
        baseline_html = baseline.get("html") or {}
        if current_html or baseline_html:
            return (
                current_html.get("title") == baseline_html.get("title")
                and current_html.get("dom_histogram") == baseline_html.get("dom_histogram")
            )
        current_json = current.get("json") or {}
        baseline_json = baseline.get("json") or {}
        if current_json or baseline_json:
            return current_json.get("structure_hash") == baseline_json.get("structure_hash")
        return current.get("body_hash") == baseline.get("body_hash")

    def state_for(self, url: str, identity: str = "anonymous") -> dict[str, Any]:
        row = self.db.execute(
            "SELECT state,cooldown_until,block_count,last_classification,healthy_projection,current_proxy,work_cursor FROM origin_state WHERE state_key=?",
            (self._state_key(url, identity),),
        ).fetchone()
        if row is None:
            return {"state": "HEALTHY", "cooldown_until": 0.0, "block_count": 0, "last_classification": "", "healthy_projection": {}, "current_proxy": "", "work_cursor": {}}
        state, cooldown, count, classification, healthy, current_proxy, work_cursor = row
        if state == "COOLING_DOWN" and float(cooldown) <= self.now():
            state = "PROBING_RECOVERY"
        return {"state": state, "cooldown_until": float(cooldown), "block_count": int(count), "last_classification": classification, "healthy_projection": json.loads(healthy), "current_proxy": current_proxy, "work_cursor": json.loads(work_cursor)}

    def _ensure_state(self, url: str, identity: str) -> str:
        key = self._state_key(url, identity)
        self.db.execute(
            "INSERT OR IGNORE INTO origin_state(state_key,state,cooldown_until,block_count,last_classification,healthy_projection) VALUES(?,?,?,?,?,?)",
            (key, "HEALTHY", 0.0, 0, "", "{}"),
        )
        return key

    def set_current_proxy(self, url: str, proxy: str, *, identity: str = "anonymous") -> None:
        key = self._ensure_state(url, identity)
        self.db.execute("UPDATE origin_state SET current_proxy=? WHERE state_key=?", (str(proxy), key))
        self.db.commit()

    def save_work_cursor(self, url: str, cursor: dict[str, Any], *, identity: str = "anonymous") -> None:
        key = self._ensure_state(url, identity)
        self.db.execute("UPDATE origin_state SET work_cursor=? WHERE state_key=?", (json.dumps(cursor, sort_keys=True), key))
        self.db.commit()

    def set_cooldown(self, url: str, classification: str, until: float, identity: str = "anonymous") -> None:
        self.db.execute(
            """INSERT INTO origin_state(state_key,state,cooldown_until,block_count,last_classification,healthy_projection)
            VALUES(?,?,?,?,?,?) ON CONFLICT(state_key) DO UPDATE SET state=excluded.state,cooldown_until=excluded.cooldown_until,last_classification=excluded.last_classification""",
            (self._state_key(url, identity), "COOLING_DOWN", until, 1, classification, "{}"),
        )
        self.db.commit()

    def raw_request(self, spec: RequestSpec, **kwargs: Any) -> Any:
        identity = self.identity_pool.switch(spec.identity)
        headers = identity.headers()
        if identity.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(identity.cookies.items())
            )
        headers.update(spec.headers)
        return self.transport.request(spec.method, spec.url, headers=headers, params=spec.params, data=spec.data, json=spec.json, timeout=spec.timeout, **kwargs)

    def request(self, spec: RequestSpec) -> BrokerOutcome:
        state = self.state_for(spec.url, spec.identity)
        if state["state"] == "HARD_BLOCKED":
            return BrokerOutcome(
                Classification.SOFT_BAN,
                1.0,
                missing_inputs=["hard_blocked"],
                next_actions=["stop_active_queue"],
            )
        if state["state"] == "COOLING_DOWN":
            return BrokerOutcome(Classification.SOFT_BAN, 1.0, missing_inputs=["cooldown_active"], next_actions=["wait_for_recovery_probe"])
        response = self.raw_request(spec)
        outcome = self.classify_response(spec, response)
        baseline = state["healthy_projection"]
        html = outcome.projection.get("html") or {}
        if (
            outcome.classification is Classification.ALLOWED_APP
            and baseline
            and html
            and not html.get("forms")
            and not html.get("links")
            and block_cluster_similarity(outcome.projection, baseline) < 0.60
        ):
            outcome = BrokerOutcome(
                Classification.SOFT_BAN,
                0.85,
                next_actions=["cool_down_target"],
                projection=outcome.projection,
            )
        self._record(spec.url, spec.identity, outcome)
        artifact = self.artifacts.write(
            {
                "request": {"method": spec.method, "url": spec.url, "mode": spec.mode},
                "classification": outcome.classification.value,
                "confidence": outcome.confidence,
                "projection": outcome.projection,
                "body": outcome.projection.get("body_sample", ""),
            },
            mode=spec.mode,
            target_id=self._origin(spec.url),
            protected=spec.mode in {"verify", "race", "oast"},
        )
        if artifact.stored:
            outcome.evidence_ids.append(f"artifact:{artifact.digest}")
        elif artifact.reason:
            outcome.missing_inputs.append(artifact.reason)
        return outcome

    def run_probe(self, spec: RequestSpec, *, clean_url: str) -> BrokerOutcome:
        clean = RequestSpec("GET", clean_url, mode="probe", identity=spec.identity)
        baseline = self.request(clean)
        probe = self.request(spec)
        post = self.request(clean)
        controls = [baseline.projection, probe.projection, post.projection]
        probe.controls = controls
        if any(item.classification is not Classification.ALLOWED_APP for item in (baseline, probe, post)):
            for item in (baseline, probe, post):
                if item.classification is not Classification.ALLOWED_APP:
                    item.controls = controls
                    return item
        probe.controls = controls
        return probe

    def recovery_probe(self, url: str, identity: str = "anonymous") -> BrokerOutcome:
        origin = self._origin(url) + "/"
        spec = RequestSpec(
            "GET",
            origin,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,application/xhtml+xml"},
            identity=identity,
        )
        previous = self.state_for(url, identity)
        response = self.raw_request(spec)
        outcome = self.classify_response(spec, response)
        baseline = previous["healthy_projection"]
        if (
            outcome.classification is Classification.ALLOWED_APP
            and baseline
            and not self._matches_healthy_baseline(outcome.projection, baseline)
        ):
            outcome = BrokerOutcome(
                Classification.SOFT_BAN,
                0.9,
                next_actions=["cool_down_target"],
                projection=outcome.projection,
            )
        self._record(origin, identity, outcome)
        return outcome
