"""Measure deterministic Event Kernel replay on a fixed 10,000-event log."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.workflow.event_kernel.replay import inspect_event_log
from core.workflow.event_kernel.service import EventKernel


EVENT_COUNT = 10_000
WARMUPS = 3
MEASURED_RUNS = 10


def _percentile_95(samples: list[float]) -> float:
    return sorted(samples)[int((len(samples) - 1) * 0.95)]


def _measure(workspace_root: Path, slug: str) -> tuple[float, float, int]:
    kernel = EventKernel(workspace_root)
    started = time.perf_counter()
    state = kernel.materialize(slug)
    replay_seconds = time.perf_counter() - started
    started = time.perf_counter()
    recovered = kernel.recover_memory_outbox(slug)
    recovery_seconds = time.perf_counter() - started
    return replay_seconds, recovery_seconds, len(state.outbox) + len(recovered)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-log", type=Path, required=True)
    parser.add_argument("--slug", required=True)
    arguments = parser.parse_args()

    source = arguments.event_log.resolve()
    replay = inspect_event_log(source, slug=arguments.slug)
    if replay.issue is not None:
        raise SystemExit(f"fixture is invalid: {replay.issue.kind.value}")
    if replay.event_count != EVENT_COUNT:
        raise SystemExit(
            f"fixture must contain exactly {EVENT_COUNT} events, got {replay.event_count}"
        )

    with tempfile.TemporaryDirectory(prefix="hunter-event-kernel-benchmark-") as directory:
        root = Path(directory)
        destination = root / "cases" / arguments.slug / "workflow.events.jsonl"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(source, destination)
        for _ in range(WARMUPS):
            _measure(root, arguments.slug)
        samples = [_measure(root, arguments.slug) for _ in range(MEASURED_RUNS)]

    replay_samples = [sample[0] for sample in samples]
    recovery_samples = [sample[1] for sample in samples]
    print(json.dumps({
        "event_count": EVENT_COUNT,
        "fixture_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "warmups": WARMUPS,
        "measured_runs": MEASURED_RUNS,
        "replay_seconds": {
            "median": statistics.median(replay_samples),
            "p95": _percentile_95(replay_samples),
        },
        "recovery_seconds": {
            "median": statistics.median(recovery_samples),
            "p95": _percentile_95(recovery_samples),
        },
        "outbox_and_recovery_entries": samples[0][2],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
