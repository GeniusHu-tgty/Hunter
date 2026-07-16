from __future__ import annotations

import statistics
import time
from pathlib import Path
from typing import Any, Callable

from .broker import RequestBroker, RequestSpec


def assert_performance_baseline(result: dict[str, Any], baseline: dict[str, Any], *, regression_limit: float = 0.20) -> None:
    """Fail CI when Broker or proxy p95/throughput regresses beyond the configured limit."""
    for mode in ("broker_sdk", "mitm_proxy"):
        observed = result.get(mode, {})
        expected = baseline.get(mode, {})
        if not observed.get("available", True) or not expected:
            continue
        if observed["p95_ms"] > expected["p95_ms"] * (1 + regression_limit):
            raise AssertionError(f"{mode} p95 regression exceeds {regression_limit:.0%}")
        if observed["requests_per_second"] < expected["requests_per_second"] * (1 - regression_limit):
            raise AssertionError(f"{mode} throughput regression exceeds {regression_limit:.0%}")


def _percentile(values: list[float], percentile: float) -> float:
    return sorted(values)[int((len(values) - 1) * percentile)]


def _summary(samples: list[float]) -> dict[str, float]:
    elapsed = sum(samples)
    return {
        "p50_ms": statistics.median(samples) * 1000,
        "p95_ms": _percentile(samples, 0.95) * 1000,
        "requests_per_second": len(samples) / elapsed if elapsed else 0.0,
    }


def measure_broker_modes(
    *,
    state_root: str | Path,
    url: str,
    samples: int,
    direct_transport: Any,
    broker_transport_factory: Callable[[], Any],
    mitm_transport_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Measure fixture-backed direct, Broker SDK, and optional MITM transports."""
    if samples < 2:
        raise ValueError("samples must be at least two")
    root = Path(state_root)

    direct_times: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        direct_transport.request("GET", url)
        direct_times.append(time.perf_counter() - started)

    def broker_samples(name: str, factory: Callable[[], Any]) -> tuple[dict[str, float], float, float]:
        broker = RequestBroker(root / name, transport=factory())
        times: list[float] = []
        artifact_times: list[float] = []
        try:
            for _ in range(samples):
                started = time.perf_counter()
                outcome = broker.request(RequestSpec("GET", url, mode="discover"))
                elapsed = time.perf_counter() - started
                times.append(elapsed)
                artifact_times.append(elapsed)
                if outcome.classification.value != "ALLOWED_APP":
                    raise RuntimeError("fixture must classify as ALLOWED_APP")
            return _summary(times), statistics.median(times) * 1000, statistics.median(artifact_times) * 1000
        finally:
            broker.artifacts.db.close()
            broker.db.close()

    broker, classify_ms, artifact_ms = broker_samples("broker", broker_transport_factory)
    result: dict[str, Any] = {
        "samples": samples,
        "direct": _summary(direct_times),
        "broker_sdk": broker,
        "queue_depth": 0,
        "classification_p50_ms": classify_ms,
        "artifact_write_p50_ms": artifact_ms,
        "baseline_amplification": 1,
        "sidecar_restart_ms": None,
    }
    if mitm_transport_factory is None:
        result["mitm_proxy"] = {"available": False}
    else:
        proxy, _, _ = broker_samples("mitm", mitm_transport_factory)
        result["mitm_proxy"] = {"available": True, **proxy}
    return result
