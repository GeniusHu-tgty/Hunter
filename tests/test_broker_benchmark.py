import pytest

from core.request_broker.benchmark import assert_performance_baseline, measure_broker_modes


class Response:
    status_code = 200
    text = "<title>Fixture</title><main>healthy fixture response</main>"
    headers = {"Content-Type": "text/html"}
    url = "https://fixture.test/"
    history = []
    cookies = {}


class Transport:
    def request(self, *_args, **_kwargs):
        return Response()


def test_fixture_benchmark_reports_required_timing_dimensions(tmp_path):
    result = measure_broker_modes(
        state_root=tmp_path,
        url="https://fixture.test/",
        samples=3,
        direct_transport=Transport(),
        broker_transport_factory=Transport,
    )

    assert result["direct"]["p95_ms"] >= 0
    assert result["broker_sdk"]["requests_per_second"] > 0
    assert result["mitm_proxy"] == {"available": False}
    assert {"queue_depth", "classification_p50_ms", "artifact_write_p50_ms", "baseline_amplification", "sidecar_restart_ms"} <= set(result)


def test_performance_baseline_rejects_more_than_twenty_percent_p95_regression():
    with pytest.raises(AssertionError, match="p95"):
        assert_performance_baseline(
            {"broker_sdk": {"p95_ms": 121, "requests_per_second": 100}},
            {"broker_sdk": {"p95_ms": 100, "requests_per_second": 100}},
        )
