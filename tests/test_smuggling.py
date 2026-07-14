from collections import deque

import pytest

from core.smuggling import SmugglingReport, SmugglingScanner


def response(status=200, body=b"ok"):
    reason = b"OK" if status == 200 else b"Bad Request"
    return (
        b"HTTP/1.1 "
        + str(status).encode()
        + b" "
        + reason
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = deque(chunks)
        self.sent = b""
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, payload):
        self.sent += payload

    def recv(self, _size):
        if not self.chunks:
            return b""
        item = self.chunks.popleft()
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self):
        self.closed = True


class ScriptedConnector:
    def __init__(self, responses):
        self.responses = deque(responses)
        self.calls = []
        self.sockets = []

    def __call__(self, address, timeout):
        self.calls.append((address, timeout))
        sock = FakeSocket([self.responses.popleft()])
        self.sockets.append(sock)
        return sock


def test_scan_builds_conflicting_raw_payloads_and_reports_safe_results():
    two_responses = response(body=b"first") + response(body=b"probe")
    connector = ScriptedConnector([two_responses] * 6)
    scanner = SmugglingScanner(
        "http://example.test/app",
        connection_factory=connector,
        clock=lambda: 10.0,
    )

    report = scanner.scan()

    assert isinstance(report, SmugglingReport)
    assert set(report.results) == {"CL.TE", "TE.CL", "TE.TE"}
    assert all(result.verdict == "safe" for result in report.results.values())
    assert all(result.confirmed is False for result in report.results.values())
    assert all(result.response_time == 0.0 for result in report.results.values())
    assert connector.calls == [(("example.test", 80), 5.0)] * 6

    payloads = {name: result.payload for name, result in report.results.items()}
    assert b"Content-Length:" in payloads["CL.TE"]
    assert b"Transfer-Encoding: chunked" in payloads["CL.TE"]
    assert b"Content-Length:" in payloads["TE.CL"]
    assert b"Transfer-Encoding: chunked" in payloads["TE.CL"]
    assert b"Transfer-Encoding: chunked0" in payloads["TE.TE"]
    assert all(b"GET /__hunter_smuggling_probe" in payload for payload in payloads.values())


def test_cl_te_marks_vulnerable_when_follow_up_response_is_swallowed():
    baseline = response(body=b"first") + response(body=b"probe")
    swallowed = response(body=b"first")
    connector = ScriptedConnector(
        [baseline, swallowed, baseline, baseline, baseline, baseline]
    )

    result = SmugglingScanner(
        "http://example.test", connection_factory=connector
    ).scan().results["CL.TE"]

    assert result.verdict == "vulnerable"
    assert result.confirmed is True
    assert result.confirmation == "follow_up_swallowed"
    assert result.baseline_response_count == 2
    assert result.response_count == 1


def test_te_cl_marks_vulnerable_when_body_is_truncated():
    baseline = response(body=b"normal-body") + response(body=b"probe")
    truncated = response(status=400, body=b"truncated request")
    connector = ScriptedConnector(
        [baseline, baseline, baseline, truncated, baseline, baseline]
    )

    result = SmugglingScanner(
        "http://example.test", connection_factory=connector
    ).scan().results["TE.CL"]

    assert result.verdict == "vulnerable"
    assert result.confirmed is True
    assert result.confirmation == "body_truncated"
    assert result.status_codes == [400]
    assert result.body_different is True


def test_te_te_uses_obfuscated_header_and_detects_response_differential():
    baseline = response(body=b"normal") + response(body=b"probe")
    differential = response(status=400, body=b"invalid transfer encoding")
    connector = ScriptedConnector(
        [baseline, baseline, baseline, baseline, baseline, differential]
    )

    result = SmugglingScanner(
        "http://example.test", connection_factory=connector
    ).scan().results["TE.TE"]

    assert result.verdict == "vulnerable"
    assert result.confirmed is True
    assert result.confirmation == "obfuscated_te_differential"
    assert b"Transfer-Encoding: chunked0" in result.payload


def test_connection_failure_returns_inconclusive_report_instead_of_raising():
    def failing_connector(_address, _timeout):
        raise OSError("connection refused")

    report = SmugglingScanner(
        "https://secure.example", connection_factory=failing_connector
    ).scan()

    assert set(report.results) == {"CL.TE", "TE.CL", "TE.TE"}
    for result in report.results.values():
        assert result.verdict == "inconclusive"
        assert result.confirmed is False
        assert "connection refused" in result.error


def test_invalid_target_is_reported_for_every_technique():
    report = SmugglingScanner("not-a-url").scan()

    assert all(result.verdict == "inconclusive" for result in report.results.values())
    assert all("http:// or https://" in result.error for result in report.results.values())


def test_verdict_rejects_unknown_values():
    with pytest.raises(ValueError):
        SmugglingScanner("http://example.test")._result(
            technique="CL.TE", payload=b"", verdict="maybe"
        )


def test_large_timing_delta_is_reported_as_inconclusive_signal():
    baseline = response(body=b"first") + response(body=b"probe")
    connector = ScriptedConnector([baseline] * 6)
    timestamps = iter([
        0.0, 0.1, 1.0, 4.5,
        5.0, 5.1, 6.0, 6.1,
        7.0, 7.1, 8.0, 8.1,
    ])

    result = SmugglingScanner(
        "http://example.test",
        connection_factory=connector,
        clock=lambda: next(timestamps),
        delay_threshold=2.0,
    ).scan().results["CL.TE"]

    assert result.verdict == "inconclusive"
    assert result.confirmed is False
    assert result.confirmation == "timing_anomaly"
    assert result.response_time == pytest.approx(3.5)
