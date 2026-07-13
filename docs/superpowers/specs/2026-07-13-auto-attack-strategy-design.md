# Automatic Attack Strategy Design

**Goal:** Turn detected technology-stack fingerprints into explainable, deferred attack recommendations and inject them into the unified scanner attack queue.

## Architecture

`UnifiedOrchestrationBridge._auto_attack_strategy(fingerprints)` is a passive strategy compiler. It reads stack recommendations from `PatternEngine`, WAF technique rankings from `TechniqueMemory`, and recognized fingerprint metadata from `FingerprintDatabase`. It also contains the required product-to-clue catalog locally so the behavior remains available when the seeded database is incomplete.

Each compiled item carries the requested recommendation contract (`strategy_id`, `title`, `tool`, `tool_args`, `priority`, and `reason`) plus the existing queue contract (`kind`, `target`, `method`, and `parameters`). `stage_attack_surface()` appends, de-duplicates, priority-sorts, and caps the combined queue. Existing queue items without a priority are treated as `P2` and keep their original relative order.

## Strategy Sources

1. `PatternEngine.recommend_stack(fingerprints)` contributes common stack vulnerability types and follow-up checks.
2. `TechniqueMemory.best_for_waf(fingerprints.get("waf"))` contributes ranked WAF-aware techniques. Empty or unavailable results are ignored.
3. The local 30+ entry stack clue catalog contributes concrete product paths and attack hints. `FingerprintDatabase.list()` is queried to enrich recognized records with default endpoints, authentication metadata, and CVEs when available.
4. If no source yields a specialized item, a single baseline `hunter_scan_plan` recommendation is emitted.

All source calls are bounded by exception handling so a missing memory database or test double cannot abort orchestration.

## Queue and Execution

Generated recommendations are appended to the existing endpoint-derived queue and sorted by `P0`, `P1`, then `P2`. The profile's `max_attack_surfaces` limit is applied after sorting. During attack execution, entries carrying `tool/tool_args` produce a deferred handoff using that tool; legacy entries continue through the current `kind` routing.

The feature only creates deferred recommendations. It does not execute high-impact actions or bypass the existing approval and evidence gates.

## Testing

Tests cover:

- known CAS/VSB/WordPress fingerprint mappings;
- PatternEngine and TechniqueMemory empty or failing queries;
- WAF recommendations and stable priority ordering;
- queue de-duplication and compatibility with legacy queue items;
- execution handoffs generated from `tool_args`.
