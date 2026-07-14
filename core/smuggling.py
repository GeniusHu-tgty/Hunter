"""Raw-socket HTTP request smuggling detection."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import socket
import ssl
import time
from typing import Callable, Literal
from urllib.parse import urlsplit


Verdict = Literal["vulnerable", "safe", "inconclusive"]
TECHNIQUES = ("CL.TE", "TE.CL", "TE.TE")
VALID_VERDICTS = {"vulnerable", "safe", "inconclusive"}


@dataclass(frozen=True)
class TechniqueResult:
    technique: str
    verdict: Verdict
    payload: bytes
    response_time: float = 0.0
    confirmed: bool = False
    confirmation: str = "not_confirmed"
    error: str | None = None
    status_codes: list[int] = field(default_factory=list)
    baseline_status_codes: list[int] = field(default_factory=list)
    response_count: int = 0
    baseline_response_count: int = 0
    body_different: bool = False


@dataclass(frozen=True)
class SmugglingReport:
    target: str
    results: dict[str, TechniqueResult]

    @property
    def vulnerable(self) -> bool:
        return any(result.verdict == "vulnerable" for result in self.results.values())


@dataclass(frozen=True)
class _RawExchange:
    raw: bytes
    elapsed: float
    error: str | None = None


@dataclass(frozen=True)
class _ParsedResponse:
    status_codes: list[int]
    bodies: list[bytes]

    @property
    def count(self) -> int:
        return len(self.status_codes)


class SmugglingScanner:
    """Detect HTTP/1.1 request desynchronization with raw socket payloads."""

    def __init__(
        self,
        target: str,
        *,
        timeout: float = 5.0,
        delay_threshold: float = 2.0,
        connection_factory: Callable[..., socket.socket] | None = None,
        ssl_context_factory: Callable[[], ssl.SSLContext] | None = None,
        clock: Callable[[], float] | None = None,
        receive_size: int = 65536,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        self.target = target
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.connection_factory = connection_factory or socket.create_connection
        self.ssl_context_factory = ssl_context_factory or ssl.create_default_context
        self.clock = clock or time.monotonic
        self.receive_size = receive_size
        self.max_response_bytes = max_response_bytes

        parsed = urlsplit(target)
        self._target_error = None
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            self._target_error = "target must include http:// or https:// and a hostname"
            self.scheme = parsed.scheme
            self.host = parsed.hostname or ""
            self.port = 0
            self.path = "/"
            return

        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query

    def scan(self) -> SmugglingReport:
        payloads = self._build_payloads()
        if self._target_error:
            return SmugglingReport(
                target=self.target,
                results={
                    technique: self._result(
                        technique=technique,
                        payload=payload,
                        verdict="inconclusive",
                        error=self._target_error,
                    )
                    for technique, payload in payloads.items()
                },
            )

        results = {}
        for technique in TECHNIQUES:
            payload = payloads[technique]
            baseline = self._exchange(self._baseline_payload())
            attack = self._exchange(payload)
            results[technique] = self._analyze(technique, payload, baseline, attack)
        return SmugglingReport(target=self.target, results=results)

    def _build_payloads(self) -> dict[str, bytes]:
        host_header = self._host_header()
        probe = self._probe_request(host_header)
        common = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: Hunter-Smuggling-Scanner/1.0\r\n"
            "Connection: keep-alive\r\n"
        ).encode("ascii", "strict")

        cl_te_body = b"0\r\n\r\nG"
        cl_te = (
            common
            + f"Content-Length: {len(cl_te_body)}\r\n".encode()
            + b"Transfer-Encoding: chunked\r\n\r\n"
            + cl_te_body
            + probe
        )

        te_cl_body = b"5\r\nHELLO\r\n0\r\n\r\n"
        te_cl = (
            common
            + b"Content-Length: 4\r\n"
            + b"Transfer-Encoding: chunked\r\n\r\n"
            + te_cl_body
            + probe
        )

        te_te_body = b"0\r\n\r\n"
        te_te = (
            common
            + f"Content-Length: {len(te_te_body)}\r\n".encode()
            + b"Transfer-Encoding: chunked\r\n"
            + b"Transfer-Encoding: chunked0\r\n\r\n"
            + te_te_body
            + probe
        )
        return {"CL.TE": cl_te, "TE.CL": te_cl, "TE.TE": te_te}

    def _baseline_payload(self) -> bytes:
        host_header = self._host_header()
        return (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: Hunter-Smuggling-Scanner/1.0\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii", "strict") + self._probe_request(host_header)

    def _probe_request(self, host_header: str) -> bytes:
        return (
            "GET /__hunter_smuggling_probe HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: Hunter-Smuggling-Scanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", "strict")

    def _host_header(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        return self.host if self.port in {0, default_port} else f"{self.host}:{self.port}"

    def _exchange(self, payload: bytes) -> _RawExchange:
        started = self.clock()
        sock = None
        data = bytearray()
        try:
            sock = self.connection_factory((self.host, self.port), self.timeout)
            sock.settimeout(self.timeout)
            if self.scheme == "https":
                context = self.ssl_context_factory()
                sock = context.wrap_socket(sock, server_hostname=self.host)
                sock.settimeout(self.timeout)
            sock.sendall(payload)
            while len(data) < self.max_response_bytes:
                try:
                    chunk = sock.recv(min(self.receive_size, self.max_response_bytes - len(data)))
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                data.extend(chunk)
            return _RawExchange(raw=bytes(data), elapsed=self.clock() - started)
        except Exception as exc:
            return _RawExchange(
                raw=bytes(data),
                elapsed=max(0.0, self.clock() - started),
                error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _analyze(
        self,
        technique: str,
        payload: bytes,
        baseline_exchange: _RawExchange,
        attack_exchange: _RawExchange,
    ) -> TechniqueResult:
        error = attack_exchange.error or baseline_exchange.error
        if error:
            return self._result(
                technique=technique,
                payload=payload,
                verdict="inconclusive",
                response_time=attack_exchange.elapsed,
                error=error,
            )

        baseline = self._parse_responses(baseline_exchange.raw)
        attack = self._parse_responses(attack_exchange.raw)
        body_different = attack.bodies != baseline.bodies
        timing_delta = attack_exchange.elapsed - baseline_exchange.elapsed
        common = {
            "technique": technique,
            "payload": payload,
            "response_time": attack_exchange.elapsed,
            "status_codes": attack.status_codes,
            "baseline_status_codes": baseline.status_codes,
            "response_count": attack.count,
            "baseline_response_count": baseline.count,
            "body_different": body_different,
        }

        if baseline.count == 0 or attack.count == 0:
            return self._result(
                **common,
                verdict="inconclusive",
                confirmation="no_complete_http_response",
            )

        swallowed = baseline.count >= 2 and attack.count < baseline.count
        status_different = attack.status_codes != baseline.status_codes

        if technique == "CL.TE" and swallowed:
            return self._result(
                **common,
                verdict="vulnerable",
                confirmed=True,
                confirmation="follow_up_swallowed",
            )

        if technique == "TE.CL" and (
            swallowed or (status_different and body_different)
        ):
            return self._result(
                **common,
                verdict="vulnerable",
                confirmed=True,
                confirmation="body_truncated",
            )

        if technique == "TE.TE" and (
            swallowed or (status_different and body_different)
        ):
            return self._result(
                **common,
                verdict="vulnerable",
                confirmed=True,
                confirmation="obfuscated_te_differential",
            )

        if timing_delta >= self.delay_threshold:
            return self._result(
                **common,
                verdict="inconclusive",
                confirmation="timing_anomaly",
            )

        return self._result(**common, verdict="safe")

    def _result(
        self,
        *,
        technique: str,
        payload: bytes,
        verdict: Verdict,
        response_time: float = 0.0,
        confirmed: bool = False,
        confirmation: str = "not_confirmed",
        error: str | None = None,
        status_codes: list[int] | None = None,
        baseline_status_codes: list[int] | None = None,
        response_count: int = 0,
        baseline_response_count: int = 0,
        body_different: bool = False,
    ) -> TechniqueResult:
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"invalid smuggling verdict: {verdict}")
        return TechniqueResult(
            technique=technique,
            verdict=verdict,
            payload=payload,
            response_time=response_time,
            confirmed=confirmed,
            confirmation=confirmation,
            error=error,
            status_codes=list(status_codes or []),
            baseline_status_codes=list(baseline_status_codes or []),
            response_count=response_count,
            baseline_response_count=baseline_response_count,
            body_different=body_different,
        )

    @staticmethod
    def _parse_responses(raw: bytes) -> _ParsedResponse:
        matches = list(re.finditer(rb"HTTP/1\.[01]\s+(\d{3})[^\r\n]*\r\n", raw))
        status_codes = [int(match.group(1)) for match in matches]
        bodies = []
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
            message = raw[match.start():end]
            separator = message.find(b"\r\n\r\n")
            bodies.append(message[separator + 4:] if separator >= 0 else b"")
        return _ParsedResponse(status_codes=status_codes, bodies=bodies)
