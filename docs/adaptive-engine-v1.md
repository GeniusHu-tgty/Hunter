# Hunter Adaptive Engine v1

Adaptive Engine v1 makes broad CTF and authorized security-research scans cheaper and faster by replacing the old serial pipeline with a budgeted DAG.

## Modes

| Mode | Wall budget | Tool budget | Concurrency | Compact output | Cache TTL |
|---|---:|---:|---:|---:|---:|
| `fast` (`quick`) | 180s | 10 | 4 | 16 KB | 30 min |
| `standard` | 1200s | 24 | 6 | 32 KB | 2 h |
| `deep` (`aggressive`) | 3600s | 50 | 8 | 64 KB | 6 h |

Agents in one layer run concurrently; the next layer starts only after its dependencies complete. A scan stops scheduling work when its wall-time or tool-count budget is exhausted.

## MCP tools

- `hunter_fast_scan`: low-cost compact scan.
- `hunter_scan_plan`: preview layers and budgets without network actions.
- `hunter_scan_benchmark`: deterministic simulated speed/cache/compaction benchmark.
- `hunter_cache_status`: inspect target/profile cache entries.
- `hunter_cache_clear`: clear all entries or a target/profile subset.

`hunter_scan` now uses the adaptive engine. Existing `quick` and `aggressive` values remain aliases for `fast` and `deep`.

## Result storage

Raw results are retained under `evidence/adaptive_raw/`. MCP responses contain only summary, signals, top findings, artifact path, byte ratio, and timing metrics. Cache entries are stored under `evidence/adaptive_cache/`; both directories are ignored by Git.

## Metrics

Every run reports wall time, accumulated tool time, estimated parallelism savings, tools started/skipped, timeouts, cache hit, output bytes, and compaction ratio.

## Adaptive routing and proof stop

`hunter_fast_scan` now enables signal-aware routing and proof-aware early stopping. Vulnerability agents with no supporting signals are skipped, and later DAG layers stop after a result reports `proof_status=confirmed|reproduced`. Metrics expose `routing_skipped`, `observed_signals`, and `early_stop_reason` so cost savings remain auditable.
