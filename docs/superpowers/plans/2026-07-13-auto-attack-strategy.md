# Automatic Attack Strategy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate stack-aware attack strategy recommendations during attack-surface analysis and inject them into the unified attack queue without breaking legacy orchestration.

**Architecture:** Add a passive strategy compiler to `core/unified_scanner.py`. It normalizes fingerprint values, queries pattern/WAF/fingerprint memory defensively, compiles hard-coded product clues into queue-compatible recommendation dictionaries, and lets `stage_attack_surface()` merge and sort those entries. The execution stage will honor explicit strategy tool descriptors while preserving existing `kind` behavior for legacy entries.

**Tech Stack:** Python 3.10+, pytest, existing Hunter memory services and workflow orchestrator.

---

### Task 1: Add failing tests for strategy compilation

**Files:**
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Add a test for a known stack mapping**

Add a test that supplies `{"edu": "金智 CAS", "waf": "Cloudflare"}` through fake services and asserts the returned strategy list contains:

```python
{
    "strategy_id": "weak_password_bruteforce",
    "tool": "hunter_session_execute_chain",
    "tool_args": {"chain_name": "login_to_admin"},
    "priority": "P0",
}
```

The assertion should also verify a `service` or `/lyuapServer/login` clue appears in the title/reason.

- [ ] **Step 2: Add tests for graceful empty/failing memory services**

Add one test where `recommend_stack()` and `best_for_waf()` return empty values and assert a baseline `hunter_scan_plan` recommendation is returned.

Add a second test where both methods raise `RuntimeError` and assert the helper still returns a non-empty baseline recommendation without propagating the exception.

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```powershell
python -m pytest tests/test_orchestrator.py -k "auto_attack_strategy" -q
```

Expected result: FAIL because `_auto_attack_strategy` does not exist yet.

### Task 2: Implement the passive strategy compiler

**Files:**
- Modify: `core/unified_scanner.py`

- [ ] **Step 1: Add local normalization and mapping logic inside `_auto_attack_strategy()`**

Implement the required signature:

```python
def _auto_attack_strategy(self, fingerprints: dict) -> list[dict]:
```

Normalize string and mapping fingerprint values, collect `waf`, `cms`, `edu`, `framework`, `api`, `language`, `database`, and frontend framework names, and match them case-insensitively against a local catalog containing at least the 30 required product/framework/service entries.

- [ ] **Step 2: Query the three data sources defensively**

Call `recommend_stack(fingerprints)`, `best_for_waf(fingerprints.get("waf"))`, and `FingerprintDatabase.list()` when available. Convert pattern issues, WAF technique names, and fingerprint metadata into recommendation items. Catch service exceptions and treat them as empty results.

- [ ] **Step 3: Compile the requested recommendation contract**

Generate stable strategy IDs, map clue types to existing queue kinds/tools/chains, include `tool_args`, set priorities, and include source evidence in `reason`. De-duplicate by the full serialized recommendation and add one generic baseline item when no specialized item exists.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run the same `pytest` command from Task 1 and confirm all new tests pass.

### Task 3: Inject recommendations into the attack queue

**Files:**
- Modify: `core/unified_scanner.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Add a failing queue integration test**

Call `stage_attack_surface()` with a known CMS fingerprint and one endpoint, then assert:

```python
assert queue[0]["priority"] == "P0"
assert queue[0]["strategy_id"] == "weak_password_bruteforce"
assert queue[1]["kind"] in {"authentication", "baseline"}
```

Also assert duplicate strategy entries are removed and an old queue-shaped item without `priority` remains valid.

- [ ] **Step 2: Merge, sort, de-duplicate, and cap**

Append enriched strategy entries to endpoint-derived entries, default their target to the scan target, resolve relative clue endpoints against the target URL, sort with `P0` before `P1` before `P2`, and apply `max_attack_surfaces` only after sorting.

- [ ] **Step 3: Run the queue-focused test and verify GREEN**

Run:

```powershell
python -m pytest tests/test_orchestrator.py -k "auto_attack_strategy or attack_surface" -q
```

Expected result: PASS.

### Task 4: Preserve strategy descriptors during deferred execution

**Files:**
- Modify: `core/unified_scanner.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Add a failing handoff test**

Build an attack queue item containing `tool="hunter_session_execute_chain"` and `tool_args={"chain_name": "login_to_admin"}`. Assert `stage_attack_execution()` emits a deferred handoff with that tool and chain name.

- [ ] **Step 2: Add the explicit-tool execution branch**

When a queue item has `tool/tool_args`, merge the generated target, parameters, and session dependency into the handoff arguments. Keep the current `kind` routing unchanged for queue items without an explicit tool descriptor.

- [ ] **Step 3: Run targeted orchestration regression tests**

Run:

```powershell
python -m pytest tests/test_orchestrator.py -k "attack_execution or auto_attack_strategy" -q
```

Expected result: PASS.

### Task 5: Full verification and workspace evidence

**Files:**
- Create: `D:/Open-tgtylab/exports/notes/hunter-auto-attack-strategy-20260713.md`
- Modify: `D:/Open-tgtylab/cases/hunter-skill/state.json`

- [ ] **Step 1: Run syntax and focused checks**

Run:

```powershell
python -m py_compile core/unified_scanner.py
python -m pytest tests/test_orchestrator.py -q
```

- [ ] **Step 2: Run the full Hunter test suite**

Run:

```powershell
python -m pytest -q
```

Record the exact pass/fail counts and any unrelated residual failures.

- [ ] **Step 3: Write evidence**

Write the implementation summary, test commands, counts, and changed files to `D:/Open-tgtylab/exports/notes/hunter-auto-attack-strategy-20260713.md`.

- [ ] **Step 4: Update case state**

Append a completed finding with evidence paths, update `updated_at`, and set `next_steps` to any remaining verification only. Do not overwrite unrelated existing findings.
