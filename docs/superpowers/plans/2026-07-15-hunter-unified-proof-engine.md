# Hunter Unified Proof Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every Hunter high-level workflow use one event-sourced execution path that runs eligible actions, verifies findings through `VerdictEngine`, learns only from final verdicts, and reliably cancels or resumes supervised external processes.

**Architecture:** Keep `WorkflowKernel` as the sole durable state authority. Add a deterministic `ActionPlanner`, a single `ToolBroker`, normalized evidence and outcome models, then route `hunter_auto_attack`, `hunter_unified_scan`, `hunter_auto_pentest`, and `hunter_workflow_run` through the existing `UnifiedOrchestrator` compatibility surface. Replace ad-hoc subprocess execution with a shared `ProcessSupervisor` that receives the workflow cancellation token and absolute deadline.

**Tech Stack:** Python 3.14, FastMCP, asyncio, dataclasses, SQLite, pytest, `ctypes` Windows Job Objects, PowerShell, Git.

---

## Execution Preconditions

The required P0 code currently exists in a dirty working tree. Do not run
`git reset`, `git clean`, or `git stash`. Start by retaining the current
working tree on a feature branch:

```powershell
git -C C:\Users\Administrator\.agents\skills\hunter switch -c feat/hunter-unified-proof-engine
```

Runtime session files under `sessions/` are not source artifacts and must not
be committed.

Design reference:

`docs/superpowers/specs/2026-07-15-hunter-unified-proof-engine-design.md`

## File Map

### Create

- `core/workflow/action_planner.py` — canonical action merge, filtering,
  deduplication, ordering, budget selection, and idempotency keys.
- `core/workflow/tool_broker.py` — single atomic-tool execution and deferred
  handoff boundary.
- `core/evidence/normalizer.py` — extract request, response, baseline, payload,
  reproduction count, and vulnerability class from heterogeneous tool output.
- `core/execution_context.py` — cancellation token, absolute deadline,
  correlation metadata, and context propagation.
- `core/process_supervisor.py` — active process registry, bounded streaming,
  process-tree cleanup, identity/version capture, and cancellation.
- `core/process_identity.py` — executable resolution, SHA-256 identity, and
  bounded version probing without recursive identity capture.
- `core/windows_job.py` — minimal Windows Job Object adapter.
- `tests/test_proof_engine_p0.py` — mandatory five P0 regressions.
- `tests/test_action_planner.py` — queue merge, phase/module, budget, and
  idempotency tests.
- `tests/test_evidence_pipeline.py` — evidence normalization, verdict,
  finding-specific evidence, and report projection tests.
- `tests/test_execution_context.py` — cancellation and absolute-deadline tests.
- `tests/test_process_supervisor.py` — process-tree, output bound, identity,
  deadline, and cleanup tests.
- `tests/test_process_supervisor_windows.py` — Windows Job Object and taskkill
  fallback tests.
- `tests/test_process_supervisor_posix.py` — POSIX process-group TERM/KILL
  tests.
- `tests/test_mcp_process_cancellation.py` — real MCP protocol cancellation
  propagation.
- `tests/fixtures/process_tree_parent.py` — deterministic parent/child process
  fixture.

### Modify

- `core/unified_scanner.py` — execute explicit allowlisted actions, consume the
  merged queue, produce separated outcome fields, call the evidence normalizer
  and verdict engine, and stop writing premature technique success.
- `core/workflow/models.py` — canonical action, action outcome, normalized
  evidence reference, and verification record dataclasses.
- `core/workflow/kernel.py` — action/evidence/verdict/process events,
  finding-specific promotion, report projection, handoff ingestion, and
  event-derived metrics.
- `core/workflow/__init__.py` — export the new planner and broker.
- `core/evidence/verdict_engine.py` — accept normalized metadata without
  weakening the existing baseline protections.
- `core/memory/technique_memory.py` — migrate from one overloaded `success`
  field to separated execution and verdict outcomes.
- `core/memory/target_memory.py` — persist separated attack outcomes and only
  store verified vulnerabilities.
- `core/process_runner.py` — compatibility adapter over `ProcessSupervisor`.
- `core/mcp_server.py` — use the shared process supervisor for external CLIs.
- `core/auto_sqli.py` — replace direct `subprocess.run` for sqlmap.
- `core/reverse/android_pipeline.py` — replace direct static-tool subprocesses.
- `core/stealth/captcha_handler.py` — supervise optional OCR installation.
- `core/doctor.py` — distinguish exact Hunter core tools from optional
  extension namespaces.
- `mcp_server.py` — common proof-engine factory, entry-point consolidation,
  MCP cancellation propagation, contract inventory, and legacy adapters.
- `integration-contract.json` — exact 113-tool core contract and explicit
  extension policy.
- `tests/test_orchestrator.py` — event, evidence, verdict, report, and resume
  integration coverage.
- `tests/test_orchestrator_runner.py` — compatibility runner delegates to the
  unified orchestration path.
- `tests/test_memory.py` — schema migration and verdict-only learning.
- `tests/test_workflow_kernel.py` — event materialization and idempotency.
- `tests/test_external_process_runner.py` — compatibility adapter coverage.
- `tests/test_hunter_tools_complete.py` — core versus extension parity.
- `tests/test_mcp_transport.py` — async cancellation reaches the supervisor.
- `SKILL.md`, `README.md`, `TOOLS.md` — one execution path and outcome
  semantics.
- `D:\Open-tgtylab\cases\hunter-skill\state.json` — final verified state.
- `D:\Open-tgtylab\exports\notes\hunter-unified-proof-engine-20260715.md` —
  verification evidence.
- `D:\Open-tgtylab\exports\reports\hunter-unified-proof-engine-20260715.md` —
  final implementation report.

---

### Task 0: Preserve the Current Hardening Baseline

**Files:**
- Modify only by commit: existing `core/`, `mcp_server.py`, and `tests/`
  source changes already present in the working tree.
- Exclude: `sessions/**`

- [ ] **Step 1: Record the known baseline**

Run:

```powershell
cd C:\Users\Administrator\.agents\skills\hunter
python -m pytest -q
```

Expected current result:

```text
1 failed, 708 passed
```

The expected failure is
`tests/test_hunter_tools_complete.py::test_fastmcp_registry_matches_hunter_tool_functions`.

- [ ] **Step 2: Verify the existing focused WIP**

Run:

```powershell
python -m pytest -q `
  tests/test_attack_reasoning.py `
  tests/test_external_process_runner.py `
  tests/test_orchestrator_runner.py `
  tests/test_scan_session_persistence.py `
  tests/test_mcp_transport.py
```

Expected: all selected tests pass.

- [ ] **Step 3: Check the baseline diff**

Run:

```powershell
git diff --check
git status --short
```

Expected: no whitespace errors. Confirm that `sessions/` remains untracked and
is not staged.

- [ ] **Step 4: Checkpoint source and tests without runtime sessions**

Run:

```powershell
git add core mcp_server.py tests
git diff --cached --check
git diff --cached --name-only
git commit -m "chore: checkpoint hunter hardening baseline"
```

Expected: the commit contains source and tests only. It must not contain
`sessions/browser/` or `sessions/scans/`.

---

## P0 — Correctness Before Expansion

### Task 1: Add the Five Mandatory P0 Regression Groups

**Files:**
- Create: `tests/test_proof_engine_p0.py`

- [ ] **Step 1: Write failing integration regressions**

Create `tests/test_proof_engine_p0.py` with these test shapes:

```python
from core.memory.technique_memory import TechniqueMemory
from core.unified_scanner import OrchestratorRunner, UnifiedOrchestrationBridge


class EmptyMemory:
    def best_for_waf(self, waf_type, limit=5):
        return []

    def query_target(self, target):
        return {"attack_history": []}

    def similar_targets(self, target, limit=5):
        return []


class EmptyReasoner:
    def reason(self, facts, evidence, memory):
        return []


def bridge_with_runner(runner, technique_memory=None):
    memory = EmptyMemory()
    return UnifiedOrchestrationBridge(
        {
            "auto_tool_runner": runner,
            "technique_memory": technique_memory or memory,
            "target_memory": memory,
        }
    )


def test_explicit_reasoner_action_executes_when_executor_is_injected():
    calls = []

    def runner(tool_name, arguments):
        calls.append((tool_name, dict(arguments)))
        return {
            "status": "ok",
            "data": {
                "vulnerable": False,
                "status_code": 200,
                "evidence": {
                    "request": {"url": arguments["target"]},
                    "response": {"status_code": 200, "body": "normal"},
                    "baseline_response": {
                        "status_code": 200,
                        "body": "normal",
                    },
                    "payload": "'",
                    "reproduction_count": 1,
                },
            },
        }

    bridge = bridge_with_runner(runner)
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test/search?q=1",
            "profile": {"mode": "autopilot", "name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [],
            "strategies": [
                {
                    "strategy_id": "reasoned-sqli",
                    "title": "verify q",
                    "condition": "q parameter",
                    "actions": [
                        {
                            "tool": "hunter_auto_sqli",
                            "priority": "P0",
                            "param": "q",
                            "params": {
                                "target_url": "https://example.test/search?q=1"
                            },
                        }
                    ],
                }
            ],
        }
    )

    assert [name for name, _ in calls] == ["hunter_auto_sqli"]
    assert len(result["attempts"]) == 1
    assert result["handoffs"] == []


def test_empty_reasoner_falls_back_to_general_attack_queue():
    executed = []

    class QueueBridge:
        services = {}

        def stage_memory(self, context):
            return {"memo": {"best_techniques": []}}

        def stage_recon(self, context):
            return {"observations": []}

        def stage_attack_surface(self, context):
            return {
                "attack_queue": [
                    {
                        "kind": "xss",
                        "tool": "hunter_auto_xss",
                        "target": "https://example.test/?q=hello",
                        "parameters": ["q"],
                        "priority": "P0",
                    }
                ]
            }

        def stage_attack_execution(self, context):
            executed.extend(context["attack_queue"])
            return {
                "status": "completed",
                "attempts": [{"tool": "hunter_auto_xss"}],
                "handoffs": [],
            }

        def stage_confirmation(self, context):
            return {"findings": [], "verdicts": []}

        def stage_evidence_learning(self, context):
            return {"evidence": [], "learning_updates": []}

    result = OrchestratorRunner(
        QueueBridge(),
        object(),
        EmptyReasoner(),
    ).run("https://example.test")

    assert [item["tool"] for item in executed] == ["hunter_auto_xss"]
    assert result["stage_results"]["attack_execution"]["attempts"]


def test_http_200_with_vulnerable_false_is_not_technique_success(tmp_path):
    memory = TechniqueMemory(tmp_path / "memory.db")

    def runner(tool_name, arguments):
        return {
            "status": "ok",
            "data": {
                "status_code": 200,
                "vulnerable": False,
                "evidence": {
                    "request": {"url": arguments["target"]},
                    "response": {"status_code": 200, "body": "normal"},
                    "baseline_response": {
                        "status_code": 200,
                        "body": "normal",
                    },
                    "payload": "'",
                    "reproduction_count": 1,
                },
            },
        }

    bridge = bridge_with_runner(runner, technique_memory=memory)
    execution = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test/?id=1",
            "profile": {"mode": "autopilot", "name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "sqli",
                    "tool": "hunter_auto_sqli",
                    "target": "https://example.test/?id=1",
                    "parameters": ["id"],
                }
            ],
        }
    )

    attempt = execution["attempts"][0]
    assert attempt["transport_success"] is True
    assert attempt["probe_executed"] is True
    assert attempt["vulnerability_confirmed"] is False
    assert memory.attempts(technique_name="hunter_auto_sqli") == []


def test_baseline_sql_error_cannot_be_confirmed():
    bridge = bridge_with_runner(lambda *_: {})
    result = bridge.stage_confirmation(
        {
            "target_url": "https://example.test/?id=1",
            "stage_results": {
                "attack_execution": {
                    "attempts": [
                        {
                            "action_id": "act-sqli",
                            "tool": "hunter_auto_sqli",
                            "attack_surface": "sqli",
                            "target": "https://example.test/?id=1",
                            "response": {
                                "data": {
                                    "vulnerable": False,
                                    "evidence": {
                                        "request": {
                                            "url": "https://example.test/?id=1'"
                                        },
                                        "response": {
                                            "status_code": 500,
                                            "body": "You have an error in your SQL syntax",
                                        },
                                        "baseline_response": {
                                            "status_code": 500,
                                            "body": "You have an error in your SQL syntax",
                                        },
                                        "payload": "'",
                                        "reproduction_count": 3,
                                    },
                                }
                            },
                        }
                    ]
                }
            },
        }
    )

    assert result["findings"] == []
    assert result["verdicts"][0]["verdict"] in {
        "refuted",
        "inconclusive",
    }


def test_requested_modules_phases_and_budget_limit_real_execution():
    calls = []

    def runner(tool_name, arguments):
        calls.append(tool_name)
        return {"status": "ok", "data": {"vulnerable": False}}

    bridge = bridge_with_runner(runner)
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {
                "mode": "autopilot",
                "name": "standard",
                "modules": ["sqli"],
                "requested_phases": ["vulnerability-analysis"],
                "max_tool_calls": 1,
            },
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "sqli",
                    "tool": "hunter_auto_sqli",
                    "target": "https://example.test/?id=1",
                    "parameters": ["id"],
                    "priority": "P0",
                },
                {
                    "kind": "xss",
                    "tool": "hunter_auto_xss",
                    "target": "https://example.test/?q=x",
                    "parameters": ["q"],
                    "priority": "P1",
                },
            ],
        }
    )

    assert calls == ["hunter_auto_sqli"]
    assert result["budget"]["selected_actions"] == 1
    assert result["filtered_actions"][0]["reason"] == "module_excluded"
```

- [ ] **Step 2: Run the P0 regressions**

Run:

```powershell
python -m pytest -q tests/test_proof_engine_p0.py
```

Expected: all five groups fail for the documented current gaps. Failures must
show: explicit action deferred, empty reasoner suppresses the queue, overloaded
success semantics, missing verdict list/baseline gate, and ignored filters.

- [ ] **Step 3: Commit failing regressions**

```powershell
git add tests/test_proof_engine_p0.py
git commit -m "test: reproduce proof engine correctness gaps"
```

---

### Task 2: Execute Explicit Allowlisted Actions

**Files:**
- Modify: `core/unified_scanner.py:2292-2775`
- Test: `tests/test_proof_engine_p0.py`
- Test: `tests/test_orchestrator.py`

- [ ] **Step 1: Replace the explicit-tool exclusion**

In `UnifiedOrchestrationBridge.stage_attack_execution`, replace the
`if executed and not explicit_tool` branch with an explicit execution
decision:

```python
execution_allowed = (
    executed
    and tool in explicit_tools
    and execution_mode in {"guided", "autopilot"}
)

if execution_allowed:
    result = self._invoke_tool(tool, arguments)
else:
    reason = (
        "executor_unavailable"
        if not executed
        else "policy_requires_guided_or_autopilot"
    )
    handoffs.append(
        {
            "tool": tool,
            "execution": "deferred",
            "status": "proposed",
            "reason": reason,
            "target": target,
            "attack_surface": kind,
            "preflight": preflight,
            "arguments": arguments,
        }
    )
```

Move the existing result normalization, attempt update, redirect handling,
weak-credential follow-up, completion-key update, and `attempts.append`
statements under the `if execution_allowed` branch without changing their
order. Preserve the current `explicit_tools` allowlist. Do not execute
arbitrary tool names supplied by the reasoner.

- [ ] **Step 2: Add action identity to every attempt**

Create a stable action identifier before execution:

```python
action_id = str(
    item.get("action_id")
    or item.get("reasoning_action_id")
    or hashlib.sha256(
        json.dumps(
            {
                "tool": tool,
                "target": target,
                "arguments": arguments,
            },
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()[:16]
)

attempt.update(
    {
        "action_id": action_id,
        "strategy_id": str(item.get("strategy_id") or ""),
    }
)
```

- [ ] **Step 3: Update the old deferred-only test**

Rename `test_explicit_strategy_stays_deferred_with_live_session` to
`test_explicit_strategy_executes_with_injected_executor`, retain its existing
`calls`, `execute_chain`, queue, and bridge setup, then change the assertions
to:

```python
assert len(calls) == 1
assert result["attempts"][0]["tool"] == "hunter_session_execute_chain"
assert result["handoffs"] == []
```

Add a second test using the same queue but omit
`"hunter_session_execute_chain": execute_chain` from services:

```python
def test_explicit_strategy_is_deferred_without_executor():
    bridge = UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
            "target_memory": EmptyTargetMemory(),
        }
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"mode": "guided", "name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "authentication",
                    "target": "https://example.test/login",
                    "tool": "hunter_session_execute_chain",
                    "tool_args": {
                        "chain_name": "login_to_admin",
                        "endpoint": "/login",
                    },
                }
            ],
        }
    )
    assert result["attempts"] == []
    assert result["handoffs"][0]["reason"] == "executor_unavailable"
```

- [ ] **Step 4: Run focused tests**

```powershell
python -m pytest -q `
  tests/test_proof_engine_p0.py::test_explicit_reasoner_action_executes_when_executor_is_injected `
  tests/test_orchestrator.py -k "explicit_strategy or reasoned_access_control"
```

Expected: pass.

- [ ] **Step 5: Commit**

```powershell
git add core/unified_scanner.py tests/test_proof_engine_p0.py tests/test_orchestrator.py
git commit -m "fix: execute allowlisted reasoner actions"
```

---

### Task 3: Merge General and Reasoned Queues with Real Filters

**Files:**
- Create: `core/workflow/action_planner.py`
- Modify: `core/workflow/models.py`
- Modify: `core/unified_scanner.py:2192-2290,3184-3458`
- Modify: `core/workflow/__init__.py`
- Create: `tests/test_action_planner.py`
- Test: `tests/test_proof_engine_p0.py`
- Test: `tests/test_orchestrator_runner.py`

- [ ] **Step 1: Write planner unit tests**

Create tests for:

```python
from core.workflow.action_planner import ActionPlanner


def action(tool, kind, target="https://example.test", priority="P1"):
    return {
        "tool": tool,
        "kind": kind,
        "target": target,
        "arguments": {"target": target},
        "priority": priority,
    }


def test_planner_merges_same_action_and_preserves_both_sources():
    planner = ActionPlanner()
    result = planner.plan(
        [action("hunter_auto_sqli", "sqli")],
        [
            {
                "strategy_id": "reasoned",
                "actions": [
                    {
                        "tool": "hunter_auto_sqli",
                        "priority": "P0",
                        "params": {"target": "https://example.test"},
                    }
                ],
            }
        ],
    )
    assert len(result["actions"]) == 1
    assert set(result["actions"][0]["sources"]) == {
        "attack-surface",
        "reasoner",
    }
    assert result["actions"][0]["priority"] == "P0"


def test_planner_keeps_general_queue_when_reasoner_is_empty():
    result = ActionPlanner().plan(
        [action("hunter_auto_xss", "xss")],
        [],
    )
    assert [item["tool"] for item in result["actions"]] == [
        "hunter_auto_xss"
    ]


def test_planner_filters_module_before_spending_budget():
    result = ActionPlanner().plan(
        [
            action("hunter_auto_xss", "xss", priority="P0"),
            action("hunter_auto_sqli", "sqli", priority="P1"),
        ],
        [],
        modules=["sqli"],
        max_actions=1,
    )
    assert [item["kind"] for item in result["actions"]] == ["sqli"]
    assert result["budget"]["started_actions"] == 1
    assert result["filtered_actions"][0]["reason"] == "module_excluded"


def test_planner_respects_requested_recon_only_phase():
    result = ActionPlanner().plan(
        [action("hunter_auto_sqli", "sqli")],
        [],
        requested_phases=["recon"],
    )
    assert result["actions"] == []
    assert result["filtered_actions"][0]["reason"] == "phase_excluded"


def test_planner_does_not_repeat_completed_idempotency_key():
    first = ActionPlanner().plan(
        [action("hunter_auto_sqli", "sqli")],
        [],
    )
    key = first["actions"][0]["idempotency_key"]
    second = ActionPlanner().plan(
        [action("hunter_auto_sqli", "sqli")],
        [],
        completed_keys=[key],
    )
    assert second["actions"] == []
    assert second["filtered_actions"][0]["reason"] == "already_completed"
```

Use canonical input dictionaries containing `kind`, `tool`, `target`,
`arguments`, `priority`, and `source`.

- [ ] **Step 2: Run tests and confirm the module is missing**

```powershell
python -m pytest -q tests/test_action_planner.py
```

Expected: collection failure because `core.workflow.action_planner` does not
exist.

- [ ] **Step 3: Add canonical action and budget models**

Extend `core/workflow/models.py`:

```python
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CanonicalAction:
    action_id: str
    tool: str
    target: str
    arguments: dict[str, Any]
    kind: str = "baseline"
    priority: str = "P2"
    sources: list[str] = field(default_factory=list)
    strategy_ids: list[str] = field(default_factory=list)
    idempotency_key: str = ""
    requires_approval: bool = False
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionBudget:
    max_actions: int
    proposed_actions: int = 0
    selected_actions: int = 0
    filtered_actions: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)
```

- [ ] **Step 4: Implement deterministic `ActionPlanner`**

Create `core/workflow/action_planner.py` with:

```python
import hashlib
import json

from .models import CanonicalAction


class ActionPlanner:
    PRIORITY = {"P0": 0, "P1": 1, "P2": 2}
    TOOL_KINDS = {
        "hunter_auto_sqli": "sqli",
        "hunter_auto_xss": "xss",
        "hunter_auto_ssrf": "ssrf_open_redirect",
        "hunter_auto_ssti": "ssti",
        "hunter_auto_xxe": "xxe",
        "hunter_auto_cmd": "command_injection",
        "hunter_auto_idor": "api_access_control",
        "hunter_auto_access_control": "api_access_control",
        "hunter_auto_csrf": "registration",
        "hunter_auto_jwt": "api_access_control",
        "hunter_auto_graphql": "graphql",
        "hunter_auto_websocket": "websocket",
        "hunter_auto_race": "race",
    }

    def plan(
        self,
        general_queue,
        reasoned_queue,
        *,
        modules=None,
        requested_phases=None,
        max_actions=8,
        completed_keys=None,
    ):
        actions = self._canonicalize(general_queue, "attack-surface")
        actions.extend(self._canonicalize_reasoned(reasoned_queue))
        merged = self._deduplicate(actions)
        selected = []
        filtered = []
        completed = set(completed_keys or [])
        allowed_modules = {
            str(value).casefold() for value in (modules or ["all"])
        }
        phases = {
            str(value).casefold() for value in (requested_phases or [])
        }

        for action in sorted(
            merged,
            key=lambda item: (
                self.PRIORITY.get(item.priority, 2),
                item.tool,
                item.target,
                item.idempotency_key,
            ),
        ):
            reason = self._filter_reason(
                action,
                allowed_modules=allowed_modules,
                requested_phases=phases,
                completed=completed,
            )
            if reason:
                filtered.append({**action.to_dict(), "reason": reason})
                continue
            if len(selected) >= max(0, int(max_actions)):
                filtered.append(
                    {**action.to_dict(), "reason": "budget_exhausted"}
                )
                continue
            selected.append(action.to_dict())

        return {
            "actions": selected,
            "filtered_actions": filtered,
            "budget": {
                "max_actions": max(0, int(max_actions)),
                "proposed_actions": len(merged),
                "selected_actions": len(selected),
                "filtered_actions": len(filtered),
            },
        }

    def _canonicalize(self, queue, source):
        output = []
        for raw in queue or []:
            item = dict(raw)
            arguments = dict(
                item.get("arguments")
                or item.get("tool_args")
                or {}
            )
            target = str(
                item.get("target")
                or arguments.get("target")
                or arguments.get("target_url")
                or ""
            )
            tool = str(item.get("tool") or "hunter_scan_plan")
            kind = str(
                item.get("kind")
                or self.TOOL_KINDS.get(tool)
                or "baseline"
            )
            arguments.pop("target_url", None)
            arguments["target"] = target
            output.append(
                self._make_action(
                    tool=tool,
                    target=target,
                    arguments=arguments,
                    kind=kind,
                    priority=str(item.get("priority") or "P2"),
                    source=source,
                    strategy_id=str(item.get("strategy_id") or ""),
                )
            )
        return output

    def _canonicalize_reasoned(self, queue):
        flattened = []
        for strategy in queue or []:
            strategy_id = str(strategy.get("strategy_id") or "")
            for raw in strategy.get("actions") or []:
                action = dict(raw)
                params = dict(action.get("params") or {})
                if action.get("param"):
                    params.setdefault("param", action["param"])
                flattened.append(
                    {
                        "tool": action.get("tool"),
                        "kind": action.get("kind"),
                        "priority": action.get("priority"),
                        "target": (
                            params.get("target")
                            or params.get("target_url")
                            or strategy.get("target")
                            or ""
                        ),
                        "arguments": params,
                        "strategy_id": strategy_id,
                    }
                )
        return self._canonicalize(flattened, "reasoner")

    def _make_action(
        self,
        *,
        tool,
        target,
        arguments,
        kind,
        priority,
        source,
        strategy_id,
    ):
        canonical = json.dumps(
            {
                "tool": tool,
                "target": target,
                "arguments": arguments,
                "kind": kind,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        key = hashlib.sha256(canonical.encode()).hexdigest()
        return CanonicalAction(
            action_id=f"act-{key[:16]}",
            tool=tool,
            target=target,
            arguments=arguments,
            kind=kind,
            priority=priority,
            sources=[source],
            strategy_ids=[strategy_id] if strategy_id else [],
            idempotency_key=key,
        )

    def _deduplicate(self, actions):
        merged = {}
        for action in actions:
            current = merged.get(action.idempotency_key)
            if current is None:
                merged[action.idempotency_key] = action
                continue
            current.sources = sorted(
                set(current.sources + action.sources)
            )
            current.strategy_ids = sorted(
                set(current.strategy_ids + action.strategy_ids)
            )
            if self.PRIORITY.get(action.priority, 2) < self.PRIORITY.get(
                current.priority,
                2,
            ):
                current.priority = action.priority
        return list(merged.values())

    @staticmethod
    def _filter_reason(
        action,
        *,
        allowed_modules,
        requested_phases,
        completed,
    ):
        if action.idempotency_key in completed:
            return "already_completed"
        if requested_phases == {"recon"}:
            return "phase_excluded"
        if (
            "all" not in allowed_modules
            and action.kind.casefold() not in allowed_modules
        ):
            return "module_excluded"
        return ""
```

The planner reports `selected_actions`, not `started_actions`. Actual
`started_actions` is computed by the execution stage in P0 and by
`action.started` events in P1.

Implement `_filter_reason` with exact reasons:

```python
if action.idempotency_key in completed:
    return "already_completed"
if requested_phases == {"recon"}:
    return "phase_excluded"
if "all" not in allowed_modules and action.kind.casefold() not in allowed_modules:
    return "module_excluded"
return ""
```

Generate `idempotency_key` from normalized tool, target, arguments, and proof
kind using SHA-256.

- [ ] **Step 5: Make `OrchestratorRunner` execute the planner result once**

Replace the strategy-only loop in `OrchestratorRunner.run` with:

```python
plan = ActionPlanner().plan(
    attack_surface.get("attack_queue", []),
    strategies,
    modules=profile.get("modules"),
    requested_phases=(
        config.get("requested_phases")
        or config.get("phases")
    ),
    max_actions=(
        config.get("max_tool_calls")
        or profile.get("max_tool_calls")
        or 8
    ),
    completed_keys=target_info.get("completed_attacks", []),
)
target_info["attack_queue"] = plan["actions"]
target_info["filtered_actions"] = plan["filtered_actions"]
target_info["budget"] = plan["budget"]

execution = self._run_stage(
    "attack_execution",
    self.bridge.stage_attack_execution,
    target_info,
)
self._apply_stage(target_info, "attack_execution", execution)
```

Delete the `_execute_strategy` loop from the active path. Keep the method only
as a compatibility helper until P1 removes its callers.

- [ ] **Step 6: Export the planner**

Add to `core/workflow/__init__.py`:

```python
from .action_planner import ActionPlanner
from .kernel import (
    ORCHESTRATOR_PROFILES,
    ORCHESTRATOR_STAGES,
    OrchestratorInterrupted,
    UnifiedOrchestrator,
    WorkflowKernel,
)
from .models import WorkflowPolicy

__all__ = [
    "ORCHESTRATOR_PROFILES",
    "ORCHESTRATOR_STAGES",
    "OrchestratorInterrupted",
    "ActionPlanner",
    "UnifiedOrchestrator",
    "WorkflowKernel",
    "WorkflowPolicy",
]
```

- [ ] **Step 7: Run focused tests**

```powershell
python -m pytest -q `
  tests/test_action_planner.py `
  tests/test_proof_engine_p0.py::test_empty_reasoner_falls_back_to_general_attack_queue `
  tests/test_proof_engine_p0.py::test_requested_modules_phases_and_budget_limit_real_execution `
  tests/test_orchestrator_runner.py
```

Expected: pass.

- [ ] **Step 8: Commit**

```powershell
git add `
  core/workflow/action_planner.py `
  core/workflow/models.py `
  core/workflow/__init__.py `
  core/unified_scanner.py `
  tests/test_action_planner.py `
  tests/test_proof_engine_p0.py `
  tests/test_orchestrator_runner.py
git commit -m "feat: merge and budget proof actions"
```

---

### Task 4: Separate Transport, Execution, Signal, and Proof Outcomes

**Files:**
- Modify: `core/workflow/models.py`
- Modify: `core/unified_scanner.py:2434-2498,2618-2719,3005-3131`
- Modify: `core/memory/technique_memory.py`
- Modify: `core/memory/target_memory.py`
- Modify: `tests/test_memory.py`
- Test: `tests/test_proof_engine_p0.py`

- [ ] **Step 1: Add failing memory migration tests**

Add:

```python
def test_technique_memory_counts_only_verified_attempts(tmp_path):
    memory = TechniqueMemory(tmp_path / "memory.db")
    memory.record_attempt(
        target_url="https://example.test",
        technique_name="hunter_auto_sqli",
        transport_success=True,
        probe_executed=True,
        signal_detected=False,
        vulnerability_confirmed=False,
        verdict="refuted",
    )
    ranked = memory.query_technique("hunter_auto_sqli")
    assert ranked["successful_attempts"] == 0


def test_legacy_success_parameter_maps_to_confirmed_for_compatibility(tmp_path):
    memory = TechniqueMemory(tmp_path / "memory.db")
    attempt = memory.record_attempt(
        target_url="https://example.test",
        technique_name="legacy",
        success=True,
    )
    assert attempt["vulnerability_confirmed"] is True
```

- [ ] **Step 2: Run tests to verify schema/signature failures**

```powershell
python -m pytest -q tests/test_memory.py -k "verified_attempts or legacy_success"
```

Expected: fail because the new fields and signature are absent.

- [ ] **Step 3: Add `ActionOutcome`**

Add to `core/workflow/models.py`:

```python
@dataclass
class ActionOutcome:
    transport_success: bool = False
    probe_executed: bool = False
    signal_detected: bool = False
    vulnerability_confirmed: bool = False
    verdict: str = "inconclusive"
    outcome: str = "unknown"

    @property
    def legacy_success(self) -> bool:
        return self.vulnerability_confirmed

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "success": self.legacy_success,
        }
```

- [ ] **Step 4: Migrate `technique_attempts` additively**

In `TechniqueMemory._initialize_schema`, after `executescript`, call:

```python
def _ensure_column(connection, table, column, declaration):
    existing = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in existing:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        )


_ensure_column(connection, "technique_attempts", "transport_success", "INTEGER NOT NULL DEFAULT 0")
_ensure_column(connection, "technique_attempts", "probe_executed", "INTEGER NOT NULL DEFAULT 0")
_ensure_column(connection, "technique_attempts", "signal_detected", "INTEGER NOT NULL DEFAULT 0")
_ensure_column(connection, "technique_attempts", "vulnerability_confirmed", "INTEGER NOT NULL DEFAULT 0")
_ensure_column(connection, "technique_attempts", "verdict", "TEXT NOT NULL DEFAULT 'inconclusive'")
_ensure_column(connection, "technique_attempts", "outcome", "TEXT NOT NULL DEFAULT 'unknown'")
```

Extend `record_attempt`:

```python
def record_attempt(
    self,
    *,
    target_url,
    technique_name,
    waf_type=None,
    success=None,
    transport_success=False,
    probe_executed=False,
    signal_detected=False,
    vulnerability_confirmed=None,
    verdict="inconclusive",
    outcome="unknown",
    attempted_at=None,
    metadata=None,
    notes="",
):
    confirmed = (
        bool(success)
        if vulnerability_confirmed is None
        else bool(vulnerability_confirmed)
    )
```

Keep the legacy `success` column synchronized with `confirmed`. Update
`_refresh_stat` to sum `vulnerability_confirmed`, not transport success.

- [ ] **Step 5: Apply the same additive migration to `attack_history`**

Add the six separated outcome columns to `TargetMemory.attack_history` and
extend `record_attack` with the same compatibility behavior.

- [ ] **Step 6: Stop recording technique memory during raw execution**

Replace `record_auto_attempt` in `stage_attack_execution` with pure outcome
normalization:

```python
def classify_execution(result):
    payload = self._result_payload(result)
    details = response_details(result)
    transport_success = bool(details["status_code"]) or str(
        result.get("status", "")
    ).casefold() in {"ok", "success", "completed"}
    probe_executed = str(result.get("status", "")).casefold() not in {
        "deferred",
        "blocked",
        "cancelled",
        "error",
        "timeout",
    }
    signal_detected = bool(
        payload.get("vulnerable")
        or payload.get("candidate")
        or payload.get("findings")
    )
    return ActionOutcome(
        transport_success=transport_success,
        probe_executed=probe_executed,
        signal_detected=signal_detected,
        vulnerability_confirmed=False,
        verdict="inconclusive",
        outcome="executed" if probe_executed else "not_executed",
    )
```

Store `outcome.to_dict()` on the attempt. Do not call
`TechniqueMemory.record_attempt` here.

- [ ] **Step 7: Run focused tests**

```powershell
python -m pytest -q `
  tests/test_memory.py `
  tests/test_proof_engine_p0.py::test_http_200_with_vulnerable_false_is_not_technique_success
```

Expected: pass.

- [ ] **Step 8: Commit**

```powershell
git add `
  core/workflow/models.py `
  core/unified_scanner.py `
  core/memory/technique_memory.py `
  core/memory/target_memory.py `
  tests/test_memory.py `
  tests/test_proof_engine_p0.py
git commit -m "fix: separate execution and proof outcomes"
```

---

### Task 5: Make `VerdictEngine` the Only Confirmation Gate

**Files:**
- Create: `core/evidence/normalizer.py`
- Modify: `core/evidence/verdict_engine.py`
- Modify: `core/unified_scanner.py:2870-3004`
- Create: `tests/test_evidence_pipeline.py`
- Test: `tests/test_proof_engine_p0.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Write failing evidence normalization tests**

Cover:

```python
from core.evidence.normalizer import EvidenceNormalizer
from core.evidence.verdict_engine import (
    Verdict,
    VerdictEngine,
    VulnType,
)
from core.unified_scanner import UnifiedOrchestrationBridge


def nested_attempt(*, body, baseline, reproductions):
    return {
        "action_id": "act-sqli",
        "tool": "hunter_auto_sqli",
        "attack_surface": "sqli",
        "target": "https://example.test/?id=1",
        "response": {
            "status": "ok",
            "error": "tool metadata must not be response evidence",
            "data": {
                "evidence": {
                    "request": {
                        "url": "https://example.test/?id=1'"
                    },
                    "response": {
                        "status_code": 500,
                        "body": body,
                    },
                    "baseline_response": {
                        "status_code": 200,
                        "body": baseline,
                    },
                    "payload": "'",
                    "reproduction_count": reproductions,
                }
            },
        },
    }


def test_normalizer_reads_nested_auto_tool_evidence():
    vuln_type, evidence = EvidenceNormalizer().normalize_attempt(
        nested_attempt(
            body="You have an error in your SQL syntax",
            baseline="normal",
            reproductions=3,
        )
    )
    assert vuln_type is VulnType.SQLI
    assert evidence.response["status_code"] == 500
    assert evidence.baseline_response["body"] == "normal"
    assert evidence.metadata["action_id"] == "act-sqli"


def test_normalizer_never_treats_tool_error_text_as_response_body():
    _, evidence = EvidenceNormalizer().normalize_attempt(
        nested_attempt(
            body="normal",
            baseline="normal",
            reproductions=1,
        )
    )
    assert evidence.response["body"] == "normal"
    assert "tool metadata" not in evidence.response["body"]


def test_baseline_collision_is_refuted_even_after_three_reproductions():
    _, evidence = EvidenceNormalizer().normalize_attempt(
        nested_attempt(
            body="You have an error in your SQL syntax",
            baseline="You have an error in your SQL syntax",
            reproductions=3,
        )
    )
    result = VerdictEngine().assess(VulnType.SQLI, evidence)
    assert result.verdict is Verdict.REFUTED


def test_likely_verdict_does_not_create_confirmed_finding():
    bridge = UnifiedOrchestrationBridge(
        {
            "evidence_normalizer": EvidenceNormalizer(),
            "verdict_engine": VerdictEngine(),
        }
    )
    result = bridge.stage_confirmation(
        {
            "target_url": "https://example.test",
            "stage_results": {
                "attack_execution": {
                    "attempts": [
                        nested_attempt(
                            body="You have an error in your SQL syntax",
                            baseline="normal",
                            reproductions=1,
                        )
                    ]
                }
            },
        }
    )
    assert result["findings"] == []
    assert result["pending_review"][0]["verdict"] == "likely"


def test_verified_verdict_contains_action_and_evidence_identity():
    bridge = UnifiedOrchestrationBridge(
        {
            "evidence_normalizer": EvidenceNormalizer(),
            "verdict_engine": VerdictEngine(),
        }
    )
    result = bridge.stage_confirmation(
        {
            "target_url": "https://example.test",
            "stage_results": {
                "attack_execution": {
                    "attempts": [
                        nested_attempt(
                            body="You have an error in your SQL syntax",
                            baseline="normal",
                            reproductions=3,
                        )
                    ]
                }
            },
        }
    )
    finding = result["findings"][0]
    assert finding["verdict"] == "verified"
    assert finding["verdict_id"] == "verdict-act-sqli"
    assert finding["evidence_keys"] == ["evidence-act-sqli"]
```

- [ ] **Step 2: Run and confirm failure**

```powershell
python -m pytest -q tests/test_evidence_pipeline.py
```

Expected: collection failure because `core.evidence.normalizer` is absent.

- [ ] **Step 3: Implement `EvidenceNormalizer`**

Create:

```python
class EvidenceNormalizer:
    KIND_TO_VULN = {
        "sqli": VulnType.SQLI,
        "sqli_xss": VulnType.SQLI,
        "xss": VulnType.XSS,
        "ssrf_open_redirect": VulnType.SSRF,
        "api_access_control": VulnType.IDOR,
        "authentication": VulnType.AUTH_BYPASS,
        "authentication_bypass": VulnType.AUTH_BYPASS,
        "registration": VulnType.CSRF,
        "file_upload": VulnType.UPLOAD,
    }

    def normalize_attempt(self, attempt):
        result = attempt.get("response") or {}
        payload = (
            result.get("data")
            if isinstance(result.get("data"), dict)
            else result
        )
        raw = (
            payload.get("evidence")
            if isinstance(payload, dict)
            and isinstance(payload.get("evidence"), dict)
            else {}
        )
        evidence = Evidence.from_mapping(
            {
                "request": raw.get("request", {}),
                "response": raw.get("response", {}),
                "baseline_response": (
                    raw.get("baseline_response")
                    or raw.get("baseline")
                    or {}
                ),
                "payload": raw.get("payload", ""),
                "reproduction_count": raw.get("reproduction_count", 0),
                "metadata": {
                    **dict(raw.get("metadata") or {}),
                    "action_id": attempt.get("action_id", ""),
                    "tool": attempt.get("tool", ""),
                    "target": attempt.get("target", ""),
                },
            }
        )
        vuln_type = self.KIND_TO_VULN.get(
            str(attempt.get("attack_surface") or "").casefold()
        )
        return vuln_type, evidence
```

Do not recurse through arbitrary nested dictionaries and convert them to one
string. Only declared `request`, `response`, `baseline_response`, `payload`,
and `metadata` fields may reach `VerdictEngine`.

- [ ] **Step 4: Rewrite `stage_confirmation`**

Use:

```python
normalizer = self._service("evidence_normalizer", EvidenceNormalizer)
verdict_engine = self._service("verdict_engine", VerdictEngine)
attempts = (
    context.get("stage_results", {})
    .get("attack_execution", {})
    .get("attempts", [])
)
verdicts = []
findings = []

for attempt in attempts:
    vuln_type, evidence = normalizer.normalize_attempt(attempt)
    if vuln_type is None:
        continue
    verdict = verdict_engine.assess(vuln_type, evidence)
    record = {
        **verdict.to_dict(),
        "verdict_id": f"verdict-{attempt.get('action_id', '')}",
        "action_id": attempt.get("action_id", ""),
        "evidence_key": f"evidence-{attempt.get('action_id', '')}",
    }
    verdicts.append(record)
    if verdict.verified:
        findings.append(
            {
                "title": f"Verified {vuln_type.value}",
                "type": vuln_type.value,
                "status": "confirmed",
                "verdict": verdict.verdict.value,
                "verdict_id": record["verdict_id"],
                "evidence_keys": [record["evidence_key"]],
                "proof_type": "verdict-engine",
                "severity": attempt.get("severity", "medium"),
            }
        )

return {
    "status": "completed",
    "verdicts": verdicts,
    "findings": findings,
    "pending_review": [
        item for item in verdicts if item["verdict"] == "likely"
    ],
    "false_positives": [
        item for item in verdicts
        if item["verdict"] in {"refuted", "inconclusive"}
    ],
}
```

`PatternEngine.match_response` may add a candidate classification before this
stage, but it must not append a confirmed finding.

- [ ] **Step 5: Update the old pattern-confirmation test**

Change the existing assertion that one SQL error is confirmed. The new test
must provide a differential baseline and at least three reproductions for a
verified result.

- [ ] **Step 6: Run focused tests**

```powershell
python -m pytest -q `
  tests/test_evidence_pipeline.py `
  tests/test_proof_engine_p0.py::test_baseline_sql_error_cannot_be_confirmed `
  tests/test_orchestrator.py -k "confirmation"
```

Expected: pass.

- [ ] **Step 7: Commit**

```powershell
git add `
  core/evidence/normalizer.py `
  core/evidence/verdict_engine.py `
  core/unified_scanner.py `
  tests/test_evidence_pipeline.py `
  tests/test_proof_engine_p0.py `
  tests/test_orchestrator.py
git commit -m "fix: gate findings through verdict engine"
```

---

### Task 6: Bind Evidence to Its Verdict and Learn After Confirmation

**Files:**
- Modify: `core/unified_scanner.py:3005-3175`
- Modify: `core/workflow/kernel.py:1131-1211,1530-1566`
- Modify: `core/memory/technique_memory.py`
- Modify: `core/memory/target_memory.py`
- Modify: `tests/test_evidence_pipeline.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Add failing finding-specific evidence tests**

Add tests asserting:

```python
assert finding["evidence_ids"] == [sqli_evidence_id]
assert unrelated_xss_evidence_id not in finding["evidence_ids"]
assert all(
    item["type"] != "pattern-confirmation"
    for item in state["evidence"]
)
assert report["findings"] == state["findings"]
```

Add a memory assertion:

```python
assert technique_attempt["verdict"] == "verified"
assert technique_attempt["vulnerability_confirmed"] is True
```

- [ ] **Step 2: Run tests and confirm current synthetic evidence behavior**

```powershell
python -m pytest -q tests/test_evidence_pipeline.py tests/test_orchestrator.py -k "evidence or report"
```

Expected: fail because all workflow evidence is attached to each finding and
synthetic `pattern-confirmation` evidence is created.

- [ ] **Step 3: Emit one normalized evidence item per attempt**

In `stage_evidence_learning`, build:

```python
evidence = []
for attempt in attempts:
    vuln_type, normalized = normalizer.normalize_attempt(attempt)
    if vuln_type is None:
        continue
    evidence.append(
        {
            "evidence_key": f"evidence-{attempt['action_id']}",
            "action_id": attempt["action_id"],
            "summary": f"{attempt['tool']} proof evidence",
            "source": attempt["tool"],
            "type": "proof-attempt",
            "confidence": "high",
            "content": normalized.to_dict(),
        }
    )
```

Join confirmation verdicts by `action_id`, then record TechniqueMemory and
TargetMemory exactly once:

```python
confirmed = verdict["verdict"] == "verified"
technique_memory.record_attempt(
    target_url=attempt["target"],
    technique_name=attempt["tool"],
    waf_type=waf,
    transport_success=attempt["transport_success"],
    probe_executed=attempt["probe_executed"],
    signal_detected=attempt["signal_detected"],
    vulnerability_confirmed=confirmed,
    verdict=verdict["verdict"],
    outcome="verified" if confirmed else verdict["verdict"],
    metadata={"action_id": attempt["action_id"]},
)
```

- [ ] **Step 4: Remove synthetic fallback evidence**

In `_register_evidence_and_findings`, maintain:

```python
evidence_key_to_id = {}
```

After registration:

```python
key = str(item.get("evidence_key") or "")
if key:
    evidence_key_to_id[key] = registered["evidence"]["id"]
```

For each finding:

```python
if finding.get("verdict") != "verified":
    continue
finding_evidence = [
    evidence_key_to_id[key]
    for key in finding.get("evidence_keys", [])
    if key in evidence_key_to_id
]
if not finding_evidence:
    continue
```

Delete the block whose summary starts with
`Pattern confirmation for {finding title}`.

- [ ] **Step 5: Project reports from promoted state**

In `_stage_report`, materialize the workflow and use:

```python
state = self.kernel.materialize(context["slug"])
raw_findings = state.get("findings", [])
evidence_by_id = {
    item["id"]: item
    for item in state.get("evidence", [])
    if isinstance(item, Mapping) and item.get("id")
}
```

For each report finding, include:

```python
finding["evidence"] = [
    evidence_by_id[evidence_id]
    for evidence_id in finding.get("evidence_ids", [])
    if evidence_id in evidence_by_id
]
```

- [ ] **Step 6: Run focused tests**

```powershell
python -m pytest -q `
  tests/test_evidence_pipeline.py `
  tests/test_memory.py `
  tests/test_orchestrator.py -k "evidence or report or learning"
```

Expected: pass.

- [ ] **Step 7: Commit**

```powershell
git add `
  core/unified_scanner.py `
  core/workflow/kernel.py `
  core/memory/technique_memory.py `
  core/memory/target_memory.py `
  tests/test_evidence_pipeline.py `
  tests/test_memory.py `
  tests/test_orchestrator.py
git commit -m "fix: bind findings to verified evidence"
```

---

### Task 7: Make the Core Tool Contract Exact Without Removing Extensions

**Files:**
- Modify: `mcp_server.py:2799-3048,4710-4765`
- Modify: `core/doctor.py`
- Modify: `integration-contract.json`
- Modify: `tests/test_hunter_tools_complete.py`
- Modify: `tests/test_mcp_v8_hardening.py`

- [ ] **Step 1: Write failing inventory tests**

Require:

```python
inventory = mcp_server._registered_tool_inventory()
assert set(inventory["core"]) == registered_functions(mcp_server)
assert all(name.startswith("re_") for name in inventory["extensions"]["reverse_lab_tools"])
assert set(inventory["core"]).isdisjoint(
    inventory["extensions"]["reverse_lab_tools"]
)
assert len(inventory["core"]) == 113
```

The FastMCP registry test becomes:

```python
assert registry == functions | extension_names
```

- [ ] **Step 2: Run the current failing contract test**

```powershell
python -m pytest -q tests/test_hunter_tools_complete.py
```

Expected: fail until inventory classification is implemented.

- [ ] **Step 3: Implement inventory classification**

Add:

```python
def _registered_tool_inventory():
    names = sorted(mcp._tool_manager._tools)
    return {
        "core": [name for name in names if name.startswith("hunter_")],
        "extensions": {
            "reverse_lab_tools": [
                name for name in names if name.startswith("re_")
            ]
        },
        "unknown": [
            name
            for name in names
            if not name.startswith(("hunter_", "re_"))
        ],
    }
```

Make `_registered_hunter_tools()` return only `inventory["core"]`.
Health and capabilities report extension counts separately.

- [ ] **Step 4: Make the contract exact**

Update `integration-contract.json`:

```json
{
  "minimum_tool_count": 113,
  "exact_core_tool_count": 113,
  "optional_extension_namespaces": ["re_"]
}
```

Add `hunter_auto_attack` and `hunter_fast_recon` to `required_tools`.

Update `HunterDoctor.contract_check` to fail when:

```python
set(registered_core) != set(required_tools)
```

Optional extension presence must not satisfy a missing core tool or create a
core mismatch.

- [ ] **Step 5: Run contract tests**

```powershell
python -m pytest -q `
  tests/test_hunter_tools_complete.py `
  tests/test_mcp_v8_hardening.py
```

Expected: pass.

- [ ] **Step 6: Commit**

```powershell
git add `
  mcp_server.py `
  core/doctor.py `
  integration-contract.json `
  tests/test_hunter_tools_complete.py `
  tests/test_mcp_v8_hardening.py
git commit -m "fix: separate core and extension tool contracts"
```

---

## P1 — One Event-Sourced Orchestration Path

### Task 8: Persist Action, Verdict, Memory, and Process Events

**Files:**
- Modify: `core/workflow/kernel.py:117-313`
- Modify: `core/workflow/models.py`
- Modify: `tests/test_workflow_kernel.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Write event materialization tests**

Add tests for these event types:

```text
facts.updated
action.proposed
action.merged
action.started
action.completed
action.deferred
action.blocked
action.cancelled
evidence.registered
verdict.created
finding.promoted
memory.projected
process.started
process.output
process.terminated
checkpoint.created
handoff.result_ingested
```

Assert that rebuilding after deleting `workflow.json` yields the same
`actions`, `tool_runs`, `verdicts`, `findings`, and metrics.

- [ ] **Step 2: Run tests to confirm event types are absent**

```powershell
python -m pytest -q tests/test_workflow_kernel.py -k "action_event or verdict_event or rebuild"
```

Expected: fail.

- [ ] **Step 3: Add explicit append helpers**

Add methods:

```python
def record_action_event(self, slug, event_type, action):
    if event_type not in {
        "action.proposed",
        "action.merged",
        "action.started",
        "action.completed",
        "action.deferred",
        "action.blocked",
        "action.cancelled",
    }:
        raise ValueError("unsupported action event")
    return self._append(slug, event_type, {"action": dict(action)})


def record_verdict(self, slug, verdict):
    return self._append(
        slug,
        "verdict.created",
        {"verdict": dict(verdict)},
    )


def record_process_event(self, slug, event_type, process):
    if event_type not in {
        "process.started",
        "process.output",
        "process.terminated",
    }:
        raise ValueError("unsupported process event")
    return self._append(slug, event_type, {"process": dict(process)})
```

Validate action transitions:

```text
pending -> started | deferred | blocked | cancelled
started -> completed | blocked | cancelled
deferred -> completed | blocked | cancelled
blocked | cancelled -> started only when attempt increments
completed -> terminal
```

Every action event contains generation, correlation ID, action ID, attempt,
and idempotency key.

- [ ] **Step 4: Materialize event-derived state**

In `materialize`, handle events without mutating unrelated projections:

```python
elif event_type.startswith("action."):
    action = dict(payload["action"])
    state.setdefault("actions", {})[action["action_id"]] = action
    if event_type == "action.started":
        state.setdefault("tool_runs", []).append(action)
        state["metrics"]["tool_calls"] = len(state["tool_runs"])
elif event_type == "verdict.created":
    verdict = dict(payload["verdict"])
    state.setdefault("verdicts", {})[
        verdict["verdict_id"]
    ] = verdict
```

Represent actions and verdicts as keyed dictionaries in materialized state to
make updates idempotent.

- [ ] **Step 5: Run event tests**

```powershell
python -m pytest -q tests/test_workflow_kernel.py tests/test_orchestrator.py -k "event or rebuild or materialize"
```

Expected: pass.

- [ ] **Step 6: Commit**

```powershell
git add core/workflow/kernel.py core/workflow/models.py tests/test_workflow_kernel.py tests/test_orchestrator.py
git commit -m "feat: persist proof engine events"
```

---

### Task 9: Introduce the Single `ToolBroker`

**Files:**
- Create: `core/workflow/tool_broker.py`
- Modify: `core/unified_scanner.py:483-558`
- Modify: `core/workflow/__init__.py`
- Create: `tests/test_tool_broker.py`

- [ ] **Step 1: Write broker tests**

Cover:

```python
from core.workflow.tool_broker import ToolBroker


def proof_action(tool="hunter_auto_sqli", key="proof-key"):
    return {
        "action_id": "act-1",
        "tool": tool,
        "arguments": {
            "target": "https://example.test",
            "password": "secret-value",
        },
        "idempotency_key": key,
    }


def test_allowlisted_tool_executes():
    calls = []
    broker = ToolBroker(
        services={
            "hunter_auto_sqli": lambda **kwargs: calls.append(kwargs)
            or {"status": "ok"}
        }
    )
    result = broker.execute(proof_action())
    assert result["status"] == "ok"
    assert len(calls) == 1


def test_unknown_tool_is_blocked_not_imported_dynamically():
    broker = ToolBroker(
        fallback_runner=lambda tool, args: {
            "status": "unexpected",
        }
    )
    result = broker.execute(proof_action("os.system"))
    assert result == {
        "status": "blocked",
        "reason": "tool_not_allowlisted",
    }


def test_missing_executor_returns_deferred_reason():
    result = ToolBroker().execute(proof_action())
    assert result == {
        "status": "deferred",
        "reason": "executor_unavailable",
    }


def test_broker_redacts_secret_arguments_in_events():
    events = []
    broker = ToolBroker(
        services={
            "hunter_auto_sqli": lambda **kwargs: {"status": "ok"}
        },
        event_sink=lambda event_type, payload: events.append(
            (event_type, payload)
        ),
    )
    broker.execute(proof_action())
    assert events[0][1]["arguments"]["password"] == "REDACTED"


def test_broker_has_no_process_local_completed_result_cache():
    calls = []
    broker = ToolBroker(
        services={
            "hunter_auto_sqli": lambda **kwargs: calls.append(kwargs)
            or {"status": "ok", "value": 1}
        }
    )
    first = broker.execute(proof_action())
    second = broker.execute(proof_action())
    assert first["value"] == second["value"] == 1
    assert len(calls) == 2
```

Idempotency is an event-sourced workflow concern. The broker must not keep a
process-local completed-result cache that can diverge from `WorkflowKernel`.

- [ ] **Step 2: Run and confirm module absence**

```powershell
python -m pytest -q tests/test_tool_broker.py
```

Expected: collection failure.

- [ ] **Step 3: Implement the broker**

Create:

```python
class ToolBroker:
    ALLOWLIST = {
        "hunter_auto_access_control",
        "hunter_auto_idor",
        "hunter_auto_sqli",
        "hunter_auto_ssrf",
        "hunter_auto_ssti",
        "hunter_auto_xss",
        "hunter_auto_xxe",
        "hunter_auto_cmd",
        "hunter_auto_csrf",
        "hunter_auto_jwt",
        "hunter_auto_graphql",
        "hunter_auto_websocket",
        "hunter_auto_race",
        "hunter_browser_navigate",
        "hunter_scan_plan",
        "hunter_session_execute_chain",
    }

    def __init__(
        self,
        services=None,
        fallback_runner=None,
        event_sink=None,
    ):
        self.services = dict(services or {})
        self.fallback_runner = fallback_runner
        self.event_sink = event_sink

    def execute(self, action):
        tool = action["tool"]
        if tool not in self.ALLOWLIST:
            return {
                "status": "blocked",
                "reason": "tool_not_allowlisted",
            }
        operation = self.services.get(tool)
        if operation is None and self.fallback_runner is None:
            return {
                "status": "deferred",
                "reason": "executor_unavailable",
            }
        if self.event_sink is not None:
            self.event_sink(
                "action.started",
                {
                    "action_id": action["action_id"],
                    "tool": tool,
                    "arguments": self._redact(action["arguments"]),
                },
            )
        result = (
            operation(**action["arguments"])
            if operation is not None
            else self.fallback_runner(tool, action["arguments"])
        )
        normalized = result if isinstance(result, dict) else {"result": result}
        return normalized

    @staticmethod
    def _redact(arguments):
        output = {}
        for key, value in dict(arguments).items():
            if any(
                token in str(key).casefold()
                for token in (
                    "password",
                    "token",
                    "authorization",
                    "cookie",
                    "secret",
                )
            ):
                output[key] = "REDACTED"
            else:
                output[key] = value
        return output
```

Use the existing supported-argument filtering and awaitable resolution helpers
inside the broker. Redact `password`, `token`, `authorization`, `cookie`, and
`secret` values before emitting event metadata.

Before calling the broker, the proof engine queries
`WorkflowKernel.completed_action_keys(slug)`. A completed key is projected
from the event log and reused without calling `ToolBroker.execute`. The broker
therefore remains stateless with respect to completion, budget, and resume.

- [ ] **Step 4: Delegate bridge invocation**

Extend `UnifiedOrchestrationBridge._invoke_tool` with an optional
`idempotency_key` parameter:

```python
def _invoke_tool(
    self,
    tool_name,
    arguments,
    idempotency_key="",
):
    key = idempotency_key or hashlib.sha256(
        json.dumps(
            {
                "tool": tool_name,
                "arguments": dict(arguments),
            },
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()
    return self._tool_broker().execute(
        {
            "action_id": f"act-{key[:16]}",
            "tool": tool_name,
            "arguments": dict(arguments),
            "idempotency_key": key,
        }
    )
```

Keep a compatibility path for direct tests that call `_invoke_tool` without an
action key. `stage_attack_execution` passes the planner-provided
`idempotency_key` when available.

- [ ] **Step 5: Run tests**

```powershell
python -m pytest -q tests/test_tool_broker.py tests/test_orchestrator.py -k "attack_execution or explicit"
```

Expected: pass.

- [ ] **Step 6: Commit**

```powershell
git add core/workflow/tool_broker.py core/workflow/__init__.py core/unified_scanner.py tests/test_tool_broker.py tests/test_orchestrator.py
git commit -m "feat: centralize atomic tool execution"
```

---

### Task 10: Route Every High-Level Entry Point Through `UnifiedOrchestrator`

**Files:**
- Modify: `mcp_server.py:118-185,431-452,2731-2776,4438-4614`
- Modify: `core/unified_scanner.py:3184-3458`
- Modify: `tests/test_orchestrator_runner.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Add factory-parity tests**

Monkeypatch one `_proof_engine` factory and call:

```text
hunter_auto_attack
hunter_unified_scan
hunter_auto_pentest
hunter_workflow_run with target/options
```

Assert all four call the same factory and produce the same canonical
`workflow_slug`, `actions`, `verdicts`, and `execution` fields for equivalent
presets.

- [ ] **Step 2: Run tests and observe multiple paths**

```powershell
python -m pytest -q tests/test_orchestrator_runner.py tests/test_orchestrator.py -k "entry_point or factory or auto_attack"
```

Expected: fail because two entry points use `OrchestratorRunner`, one defaults
to `UnifiedOrchestrator`, and `hunter_workflow_run` switches semantics.

- [ ] **Step 3: Add one engine factory**

In `mcp_server.py`:

```python
def _orchestration_services(call_mcp_tool=None):
    services = {
        "stealth_http_client": _get_stealth_client(),
        "attack_reasoner": AttackReasoner(),
        "auto_tool_runner": _orchestrator_auto_tool_runner,
    }
    if call_mcp_tool is not None:
        services["call_mcp_tool"] = call_mcp_tool
    return services


def _proof_engine(call_mcp_tool=None):
    return UnifiedOrchestrator(
        _workflow_kernel(),
        services=_orchestration_services(call_mcp_tool),
    )
```

Create one helper:

```python
def _run_proof_engine(
    *,
    target_url,
    config,
    mode,
    profile,
    modules,
    call_mcp_tool,
    base_slug,
):
    kernel = _workflow_kernel()
    slug, generation, _ = _prepare_orchestrator_workflow(
        kernel,
        base_slug=base_slug,
        target_url=target_url,
        config=config,
        mode=mode,
        profile=profile,
        modules=modules,
    )
    result = _proof_engine(call_mcp_tool).orchestrate(
        slug,
        target_url=target_url,
        modules=modules,
        policy=profile,
        resume=bool(config.get("resume", False)),
        observations=config.get("observations"),
        approval=config.get("approval"),
        checkpoint_id=config.get("checkpoint_id", ""),
    )
    return {
        "workflow_slug": slug,
        "generation": generation,
        **result,
    }
```

- [ ] **Step 4: Convert entry points to presets**

Map:

```python
hunter_auto_attack:
    profile = config.get("policy", "standard")
    modules = config.get("modules", ["all"])

hunter_unified_scan:
    profile = "standard"
    modules = phases or ["all"]
    config["requested_phases"] = list(phases or [])

hunter_auto_pentest:
    preserve current policy/mode/modules

hunter_workflow_run:
    if target_url/options are supplied, call _run_proof_engine;
    otherwise run only the existing workflow-plan actions.
```

Delete the `use_runner` branch. Keep `OrchestratorRunner` as a compatibility
adapter whose `run` calls an injected proof-engine callable; it must not own a
second temporary state model.

- [ ] **Step 5: Run entry-point tests**

```powershell
python -m pytest -q tests/test_orchestrator_runner.py tests/test_orchestrator.py -k "entry_point or auto_attack or unified_scan or auto_pentest or workflow_run"
```

Expected: pass.

- [ ] **Step 6: Commit**

```powershell
git add mcp_server.py core/unified_scanner.py tests/test_orchestrator_runner.py tests/test_orchestrator.py
git commit -m "refactor: unify high-level orchestration entry points"
```

---

### Task 11: Ingest Handoff Results Once and Resume the First Incomplete Action

**Files:**
- Modify: `core/workflow/kernel.py`
- Modify: `mcp_server.py`
- Modify: `tests/test_orchestrator.py`
- Modify: `tests/test_workflow_kernel.py`

- [ ] **Step 1: Add failing handoff and resume tests**

Cover:

```python
def test_same_handoff_result_digest_is_ingested_once(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    result = {
        "action_id": "act-1",
        "status": "completed",
        "evidence": {"response": {"status_code": 200}},
    }
    first = kernel.ingest_handoff_result(slug, result)
    second = kernel.ingest_handoff_result(slug, result)
    assert first["ingested"] is True
    assert second["ingested"] is False
    state = kernel.materialize(slug)
    assert len(state["ingested_handoff_digests"]) == 1


def test_resume_skips_completed_action_idempotency_keys(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    kernel.record_action_event(
        slug,
        "action.completed",
        {
            "action_id": "act-1",
            "idempotency_key": "key-1",
            "status": "completed",
        },
    )
    assert kernel.completed_action_keys(slug) == {"key-1"}


def test_resume_restarts_non_resumable_interrupted_action_with_new_attempt(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    kernel.record_action_event(
        slug,
        "action.started",
        {
            "action_id": "act-1",
            "idempotency_key": "key-1",
            "status": "started",
            "attempt": 1,
            "resumable": False,
        },
    )
    next_action = kernel.next_incomplete_action(slug)
    assert next_action["action_id"] == "act-1"
    assert next_action["attempt"] == 2
    assert next_action["restart_required"] is True


def test_completed_action_does_not_spend_budget_twice():
    planner = ActionPlanner()
    first = planner.plan(
        [
            {
                "tool": "hunter_auto_sqli",
                "kind": "sqli",
                "target": "https://example.test",
                "arguments": {"target": "https://example.test"},
            }
        ],
        [],
        max_actions=1,
    )
    key = first["actions"][0]["idempotency_key"]
    resumed = planner.plan(
        [
            {
                "tool": "hunter_auto_sqli",
                "kind": "sqli",
                "target": "https://example.test",
                "arguments": {"target": "https://example.test"},
            }
        ],
        [],
        max_actions=1,
        completed_keys={key},
    )
    assert resumed["budget"]["started_actions"] == 0
    assert resumed["filtered_actions"][0]["reason"] == "already_completed"
```

Use the existing `_workflow` helper in `tests/test_workflow_kernel.py`; import
`ActionPlanner` in the budget test.

- [ ] **Step 2: Implement observation ingestion**

Add `WorkflowKernel.ingest_handoff_result` and call it for each
`observations["handoff_results"]` item before stage execution:

```python
digest = hashlib.sha256(
    json.dumps(result, sort_keys=True, default=str).encode()
).hexdigest()
state = self.materialize(slug)
if digest in state.get("ingested_handoff_digests", []):
    return {"ingested": False, "digest": digest}
self._append(
    slug,
    "handoff.result_ingested",
    {"digest": digest, "result": self._json_safe(result)},
)
return {"ingested": True, "digest": digest}
```

Materialization stores the digest and indexes the result by `action_id`.

- [ ] **Step 3: Use event-derived completed keys**

Before planning:

```python
completed_keys = {
    action["idempotency_key"]
    for action in state.get("actions", {}).values()
    if action.get("status") == "completed"
}
```

Pass these keys to `ActionPlanner`.

Add:

```python
def completed_action_keys(self, slug):
    state = self.materialize(slug)
    return {
        str(action.get("idempotency_key"))
        for action in state.get("actions", {}).values()
        if action.get("status") == "completed"
        and action.get("idempotency_key")
    }


def next_incomplete_action(self, slug):
    state = self.materialize(slug)
    for action in state.get("actions", {}).values():
        if action.get("status") == "completed":
            continue
        attempt = int(action.get("attempt") or 1)
        return {
            **action,
            "attempt": attempt if action.get("resumable") else attempt + 1,
            "restart_required": not bool(action.get("resumable")),
        }
    return {}
```

- [ ] **Step 4: Checkpoint after every completed stage and cancellation**

Ensure the orchestrator appends a checkpoint after:

```text
recon
attack_surface
attack_execution
vulnerability_confirmation
evidence_learning
```

The checkpoint records the first action whose status is not completed.

- [ ] **Step 5: Run resume tests**

```powershell
python -m pytest -q tests/test_orchestrator.py tests/test_workflow_kernel.py -k "handoff or resume or idempot"
```

Expected: pass.

- [ ] **Step 6: Commit**

```powershell
git add core/workflow/kernel.py mcp_server.py tests/test_orchestrator.py tests/test_workflow_kernel.py
git commit -m "feat: ingest handoffs and resume idempotently"
```

---

## P2 — Cancellation, Deadlines, and Process Reliability

### Task 12: Add Shared Cancellation and Absolute Deadline Context

**Files:**
- Create: `core/execution_context.py`
- Create: `tests/test_execution_context.py`

- [ ] **Step 1: Write context tests**

Cover:

```python
import asyncio
import threading
import time

from core.execution_context import (
    CancellationToken,
    Deadline,
    ExecutionContext,
    current_execution_context,
    execution_scope,
)


def test_child_deadline_cannot_exceed_parent():
    parent = Deadline.after(0.05)
    child = parent.child(60)
    assert child.expires_at == parent.expires_at


def test_child_action_context_reuses_token_and_total_deadline():
    parent = ExecutionContext(
        workflow_slug="wf-test",
        token=CancellationToken(),
        deadline=Deadline.after(0.2),
    )
    child = parent.child_for_action(
        "act-1",
        30,
        attempt=2,
        idempotency_key="key-1",
    )
    assert child.token is parent.token
    assert child.deadline.expires_at == parent.deadline.expires_at
    assert child.attempt == 2
    assert child.idempotency_key == "key-1"


def test_cancellation_reason_is_shared_across_threads():
    token = CancellationToken()
    observed = []
    thread = threading.Thread(
        target=lambda: (
            token.wait(1),
            observed.append(token.reason),
        )
    )
    thread.start()
    token.cancel("mcp_cancelled")
    token.cancel("cleanup_timeout")
    thread.join(timeout=2)
    assert observed == ["mcp_cancelled"]
    assert token.reason == "mcp_cancelled"


def test_remaining_seconds_reaches_zero_without_reset():
    deadline = Deadline.after(0.01)
    time.sleep(0.03)
    assert deadline.remaining() == 0.0
    assert deadline.child(60).remaining() == 0.0


def test_contextvar_propagates_through_asyncio_to_thread():
    async def exercise():
        context = ExecutionContext(workflow_slug="wf-test")
        with execution_scope(context):
            return await asyncio.to_thread(current_execution_context)

    observed = asyncio.run(exercise())
    assert observed.workflow_slug == "wf-test"
```

- [ ] **Step 2: Run and confirm missing module**

```powershell
python -m pytest -q tests/test_execution_context.py
```

Expected: collection failure.

- [ ] **Step 3: Implement the primitives**

Create:

```python
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import threading
import time
import uuid


class CancellationToken:
    def __init__(self):
        self._event = threading.Event()
        self._reason = ""

    def cancel(self, reason="cancelled"):
        if not self._event.is_set():
            self._reason = str(reason)
            self._event.set()

    @property
    def cancelled(self):
        return self._event.is_set()

    @property
    def reason(self):
        return self._reason

    def raise_if_cancelled(self):
        if self.cancelled:
            raise ExecutionCancelled(self.reason)

    def wait(self, timeout=None):
        return self._event.wait(timeout)


@dataclass(frozen=True)
class Deadline:
    expires_at: float

    @classmethod
    def after(cls, seconds):
        return cls(time.monotonic() + max(0.0, float(seconds)))

    def remaining(self):
        return max(0.0, self.expires_at - time.monotonic())

    def child(self, seconds):
        return Deadline(
            min(
                self.expires_at,
                time.monotonic() + max(0.0, float(seconds)),
            )
        )


@dataclass
class ExecutionContext:
    correlation_id: str = field(
        default_factory=lambda: f"exec-{uuid.uuid4().hex[:16]}"
    )
    workflow_slug: str = ""
    action_id: str = ""
    attempt: int = 1
    idempotency_key: str = ""
    token: CancellationToken = field(default_factory=CancellationToken)
    deadline: Deadline = field(
        default_factory=lambda: Deadline.after(120)
    )
    event_sink: object | None = None

    def child_for_action(
        self,
        action_id,
        seconds,
        *,
        attempt,
        idempotency_key,
    ):
        return ExecutionContext(
            correlation_id=self.correlation_id,
            workflow_slug=self.workflow_slug,
            action_id=str(action_id),
            attempt=max(1, int(attempt)),
            idempotency_key=str(idempotency_key),
            token=self.token,
            deadline=self.deadline.child(seconds),
            event_sink=self.event_sink,
        )


_CURRENT = ContextVar("hunter_execution_context", default=None)


def current_execution_context():
    return _CURRENT.get()


@contextmanager
def execution_scope(context):
    reset = _CURRENT.set(context)
    try:
        yield context
    finally:
        _CURRENT.reset(reset)
```

Define `ExecutionCancelled(RuntimeError)`.

- [ ] **Step 4: Run tests**

```powershell
python -m pytest -q tests/test_execution_context.py
```

Expected: pass.

- [ ] **Step 5: Commit**

```powershell
git add core/execution_context.py tests/test_execution_context.py
git commit -m "feat: add execution cancellation context"
```

---

### Task 13: Implement Windows Job Object and Bounded Process Supervision

**Files:**
- Create: `core/windows_job.py`
- Create: `core/process_identity.py`
- Create: `core/process_supervisor.py`
- Create: `tests/fixtures/process_tree_parent.py`
- Create: `tests/test_process_supervisor.py`
- Create: `tests/test_process_supervisor_windows.py`
- Create: `tests/test_process_supervisor_posix.py`

- [ ] **Step 1: Write process fixture**

The fixture starts one child process and writes both PIDs:

```python
import json
from pathlib import Path
import subprocess
import sys
import time

pid_file = Path(sys.argv[1])
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"]
)
pid_file.write_text(
    json.dumps({"parent": __import__("os").getpid(), "child": child.pid}),
    encoding="utf-8",
)
print("parent-ready", flush=True)
while True:
    print("x" * 4096, flush=True)
    time.sleep(0.02)
```

- [ ] **Step 2: Write failing supervisor tests**

Cover:

```python
import ctypes
import json
import os
from pathlib import Path
import sys
import threading
import time

from core.execution_context import Deadline, ExecutionContext
from core.process_supervisor import ProcessSupervisor


FIXTURE = Path(__file__).parent / "fixtures" / "process_tree_parent.py"


def pid_alive(pid):
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    process = ctypes.windll.kernel32.OpenProcess(
        0x1000,
        False,
        int(pid),
    )
    if not process:
        return False
    exit_code = ctypes.c_ulong()
    ctypes.windll.kernel32.GetExitCodeProcess(
        process,
        ctypes.byref(exit_code),
    )
    ctypes.windll.kernel32.CloseHandle(process)
    return exit_code.value == 259


def test_total_deadline_terminates_parent_and_child(tmp_path):
    pid_file = tmp_path / "pids.json"
    context = ExecutionContext(deadline=Deadline.after(0.4))
    result = ProcessSupervisor().run(
        [sys.executable, str(FIXTURE), str(pid_file)],
        timeout=30,
        context=context,
        max_output_bytes=32 * 1024,
    )
    pids = json.loads(pid_file.read_text(encoding="utf-8"))
    assert result["status"] == "timeout"
    assert result["deadline_type"] == "workflow_deadline"
    assert result["cleanup"]["tree_terminated"] is True
    assert not pid_alive(pids["parent"])
    assert not pid_alive(pids["child"])


def test_cancel_by_correlation_id_terminates_tree(tmp_path):
    pid_file = tmp_path / "pids.json"
    supervisor = ProcessSupervisor()
    context = ExecutionContext(deadline=Deadline.after(30))
    holder = {}
    thread = threading.Thread(
        target=lambda: holder.setdefault(
            "result",
            supervisor.run(
                [sys.executable, str(FIXTURE), str(pid_file)],
                timeout=30,
                context=context,
            ),
        )
    )
    thread.start()
    deadline = time.monotonic() + 5
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert supervisor.cancel(
        context.correlation_id,
        "test_cancel",
    ) is True
    thread.join(timeout=5)
    assert holder["result"]["status"] == "cancelled"
    assert supervisor.active() == []


def test_output_is_bounded_but_total_bytes_are_counted(tmp_path):
    result = ProcessSupervisor().run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('x' * 2000000)",
        ],
        timeout=10,
        max_output_bytes=64 * 1024,
    )
    assert result["stdout"]["total_bytes"] == 2_000_000
    assert result["stdout"]["retained_bytes"] <= 64 * 1024
    assert result["stdout"]["truncated"] is True


def test_idle_timeout_is_distinct_from_action_deadline(tmp_path):
    result = ProcessSupervisor().run(
        [
            sys.executable,
            "-c",
            "import time; print('ready', flush=True); time.sleep(10)",
        ],
        timeout=5,
        idle_timeout=0.2,
    )
    assert result["status"] == "timeout"
    assert result["deadline_type"] == "idle_timeout"


def test_executable_identity_contains_path_and_version():
    result = ProcessSupervisor().run(
        [sys.executable, "-c", "print('ok')"],
        timeout=5,
        version_args=("--version",),
    )
    assert Path(result["identity"]["resolved_path"]).samefile(
        sys.executable
    )
    assert "Python" in result["identity"]["version_output"]


def test_active_registry_is_empty_after_cleanup(tmp_path):
    supervisor = ProcessSupervisor()
    result = supervisor.run(
        [sys.executable, "-c", "print('done')"],
        timeout=5,
    )
    assert result["status"] == "success"
    assert supervisor.active() == []
```

Use `psutil` only if already installed; otherwise verify process exit with
`os.kill(pid, 0)` on POSIX and `OpenProcess`/`GetExitCodeProcess` on Windows.

Also cover all timeout categories:

```text
start_timeout
idle_timeout
action_deadline
workflow_deadline
cleanup_timeout
```

Cancellation has highest priority, followed by workflow deadline, action
deadline, idle timeout, and normal process exit. Cleanup receives a separate,
strictly bounded deadline after business execution stops.

- [ ] **Step 3: Implement Windows Job Object adapter**

`WindowsJob` must:

```python
job = CreateJobObjectW(None, None)
limits.BasicLimitInformation.LimitFlags = (
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
)
SetInformationJobObject(
    job,
    JobObjectExtendedLimitInformation,
    byref(limits),
    sizeof(limits),
)
AssignProcessToJobObject(job, process_handle)
```

Expose a `WindowsJob` class whose `assign_pid(pid)` opens the process with
`PROCESS_SET_QUOTA | PROCESS_TERMINATE`, assigns it to the job, closes the
process handle, and returns `{"assigned": bool, "error": str}`.
`terminate(exit_code=1)` calls `TerminateJobObject` and returns whether it
succeeded. `close()` calls `CloseHandle` exactly once and clears the stored
job handle.

All handles close in `finally`. If assignment fails because the process is
already inside a non-breakaway job, return a structured failure and let the
supervisor use `taskkill /T /F`.

Prefer creating the process inside the Job Object through a supported
`STARTUPINFO.lpAttributeList["job_list"]` path so a child cannot escape between
process creation and post-spawn assignment. When that runtime path is
unavailable, use post-spawn assignment and record the fallback explicitly.

Add Windows-only tests for Job ownership, idempotent close, assignment
failure, taskkill fallback, and zero remaining fixture PIDs. Add POSIX-only
tests for `start_new_session=True`, process-group SIGTERM, SIGKILL escalation,
and zero parent/child orphans.

- [ ] **Step 4: Implement bounded output storage**

In `core/process_supervisor.py`:

```python
class BoundedOutput:
    def __init__(self, max_bytes=1024 * 1024):
        self.max_bytes = max(1024, int(max_bytes))
        self.total_bytes = 0
        self._head = bytearray()
        self._tail = bytearray()

    def feed(self, chunk):
        data = bytes(chunk)
        self.total_bytes += len(data)
        half = self.max_bytes // 2
        if len(self._head) < half:
            take = min(half - len(self._head), len(data))
            self._head.extend(data[:take])
            data = data[take:]
        if data:
            self._tail.extend(data)
            if len(self._tail) > self.max_bytes - half:
                del self._tail[: len(self._tail) - (self.max_bytes - half)]

    def result(self):
        return {
            "text": (
                bytes(self._head) + bytes(self._tail)
            ).decode("utf-8", errors="replace"),
            "total_bytes": self.total_bytes,
            "retained_bytes": len(self._head) + len(self._tail),
            "truncated": self.total_bytes > self.max_bytes,
        }
```

- [ ] **Step 5: Implement `ProcessSupervisor`**

Required public methods:

- `run(argv, *, timeout, start_timeout=5.0, idle_timeout=None,
  cleanup_timeout=5.0, env=None, cwd=None,
  stdout_limit=1024 * 1024, stderr_limit=256 * 1024, context=None,
  version_args=("--version",), capture_identity=True) -> dict`
- `cancel(correlation_id, reason="cancelled") -> bool`
- `active() -> list[dict]`
- `wait_for_cleanup(correlation_id, timeout=5.0) -> bool`

Implementation requirements:

1. Use `subprocess.Popen(command, stdout=subprocess.PIPE,
   stderr=subprocess.PIPE, text=False, shell=False, env=env, cwd=cwd,
   creationflags=creationflags, **platform_kwargs)`.
2. On Windows use `CREATE_NEW_PROCESS_GROUP` and attach `WindowsJob`.
3. On POSIX use `start_new_session=True`.
4. Reader threads feed separate `BoundedOutput` instances and update
   `last_output_at`.
5. Main loop checks token cancellation, absolute context deadline, action
   timeout, idle timeout, and process exit every 50 ms.
6. Cleanup uses Job Object termination, then `taskkill` fallback on Windows;
   `killpg` on POSIX.
7. Remove the process record from the active registry only after output pipes
   are drained or the cleanup deadline expires.
8. Return `identity`, `deadline_type`, `cleanup`, `stdout`, `stderr`,
   `elapsed_seconds`, and `correlation_id`.

Implement executable identity in `core/process_identity.py`. Record the exact
resolved executable path, SHA-256, version argv, bounded version output,
return code, and `success|timeout|unsupported|error` status. The version probe
uses the same supervisor with `capture_identity=False`, a five-second child
deadline, and at most 64 KiB output, so identity capture cannot recurse or
extend the workflow deadline.

- [ ] **Step 6: Run process tests**

```powershell
python -m pytest -q `
  tests/test_process_supervisor.py `
  tests/test_process_supervisor_windows.py `
  tests/test_process_supervisor_posix.py
```

Expected: pass with zero active records after every test.

- [ ] **Step 7: Commit**

```powershell
git add `
  core/windows_job.py `
  core/process_identity.py `
  core/process_supervisor.py `
  tests/fixtures/process_tree_parent.py `
  tests/test_process_supervisor.py `
  tests/test_process_supervisor_windows.py `
  tests/test_process_supervisor_posix.py
git commit -m "feat: supervise external process trees"
```

---

### Task 14: Replace Direct Subprocess Calls and Preserve Compatibility

**Files:**
- Modify: `core/process_runner.py`
- Modify: `core/mcp_server.py:27,44-73`
- Modify: `core/auto_sqli.py:890-936`
- Modify: `core/reverse/android_pipeline.py:293-313`
- Modify: `core/stealth/captcha_handler.py:133-149`
- Modify: `tests/test_external_process_runner.py`
- Modify: `tests/test_process_supervisor.py`

- [ ] **Step 1: Make `ExternalProcessRunner` a thin adapter**

Replace its internal `Popen` implementation:

```python
class ExternalProcessRunner:
    def __init__(self, cleanup_timeout=3.0, supervisor=None):
        self.cleanup_timeout = max(0.1, float(cleanup_timeout))
        self.supervisor = supervisor or get_process_supervisor()

    def run(self, argv, *, timeout, env=None, cwd=None):
        return self.supervisor.run(
            argv,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
```

Keep `_terminate_tree` only as a deprecated test compatibility shim that calls
the supervisor cleanup API.

- [ ] **Step 2: Migrate `HunterMCPServer.run_tool`**

Inject or obtain the shared supervisor in `HunterMCPServer.__init__`.
Pass the current execution context automatically.

- [ ] **Step 3: Migrate sqlmap deep execution**

Replace `subprocess.run`:

```python
result = get_process_supervisor().run(
    command,
    timeout=900,
    idle_timeout=120,
    max_output_bytes=1024 * 1024,
)
```

Keep request-file deletion in `finally`.

- [ ] **Step 4: Migrate Android static tools**

Use the supervisor and preserve the legacy `status`, `tool`, `command`,
`returncode`, `stdout`, and `stderr` fields.

- [ ] **Step 5: Migrate optional OCR installation**

Use the supervisor with:

```python
timeout=self.install_timeout
max_output_bytes=128 * 1024
```

Treat a nonzero return code as unavailable without raising into scan execution.

- [ ] **Step 6: Verify no unmanaged subprocess remains**

Run:

```powershell
@'
import ast, pathlib
root = pathlib.Path(".")
targets = [
    root / "core/mcp_server.py",
    root / "core/auto_sqli.py",
    root / "core/reverse/android_pipeline.py",
    root / "core/stealth/captcha_handler.py",
]
hits = []
for path in targets:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr
            in {"run", "Popen", "call", "check_call", "check_output"}
        ):
            hits.append((path.as_posix(), node.lineno, node.func.attr))
print(hits)
assert hits == []
'@ | python -
```

Expected: `[]`.

This P2 gate is intentionally limited to the four migration targets. Other
legacy utility modules that still own subprocess calls require a separate
follow-up migration and must not make this scoped P0–P2 plan unfinishable.

- [ ] **Step 7: Run focused tests**

```powershell
python -m pytest -q `
  tests/test_external_process_runner.py `
  tests/test_process_supervisor.py `
  tests/test_fast_recon.py `
  tests/test_captcha_handler.py
```

Expected: pass.

- [ ] **Step 8: Commit**

```powershell
git add `
  core/process_runner.py `
  core/process_supervisor.py `
  core/mcp_server.py `
  core/auto_sqli.py `
  core/reverse/android_pipeline.py `
  core/stealth/captcha_handler.py `
  tests/test_external_process_runner.py `
  tests/test_process_supervisor.py `
  tests/test_fast_recon.py `
  tests/test_captcha_handler.py
git commit -m "refactor: route external tools through supervisor"
```

---

### Task 15: Propagate MCP Cancellation and Total Deadlines

**Files:**
- Modify: `mcp_server.py:1252-1286`
- Modify: `mcp_server.py:2323-2351`
- Modify: `mcp_server.py:4391-4414`
- Modify: `core/workflow/tool_broker.py`
- Modify: `core/workflow/kernel.py`
- Modify: `tests/test_mcp_transport.py`
- Create: `tests/test_mcp_process_cancellation.py`
- Modify: `tests/test_execution_context.py`
- Modify: `tests/test_process_supervisor.py`

- [ ] **Step 1: Write failing MCP cancellation test**

Start a tool implementation that launches the process-tree fixture and call it
through the in-memory FastMCP session. Send a real MCP
`notifications/cancelled` message for the active request ID rather than merely
cancelling the local Python client task. Then assert:

```python
assert supervisor.active() == []
assert workflow_state["actions"][action_id]["status"] == "cancelled"
assert workflow_state["checkpoints"]
```

The test waits until the supervisor registry contains the process, sends the
protocol cancellation, and verifies that the checkpoint and process cleanup
complete before the MCP request reaches its terminal cancelled state.

- [ ] **Step 2: Add execution scope to `_safe_json_tool`**

Extract one helper used by `_execute_agent_async`, `_safe_json_tool`, and
`_async_workflow_result`. Use:

```python
context = ExecutionContext(
    deadline=Deadline.after(timeout),
)

def invoke():
    with execution_scope(context):
        return _call_with_supported_kwargs(func, *args, **kwargs)

try:
    result = await asyncio.wait_for(
        asyncio.to_thread(invoke),
        timeout=context.deadline.remaining(),
    )
except asyncio.CancelledError:
    context.token.cancel("mcp_cancelled")
    supervisor.cancel(context.correlation_id, "mcp_cancelled")
    with anyio.CancelScope(shield=True):
        await asyncio.to_thread(
            supervisor.wait_for_cleanup,
            context.correlation_id,
            5.0,
        )
        await asyncio.to_thread(
            record_cancel_and_checkpoint,
            context,
        )
    raise
except asyncio.TimeoutError:
    context.token.cancel("tool_deadline")
    supervisor.cancel(context.correlation_id, "tool_deadline")
    with anyio.CancelScope(shield=True):
        await asyncio.to_thread(
            supervisor.wait_for_cleanup,
            context.correlation_id,
            5.0,
        )
        await asyncio.to_thread(
            record_cancel_and_checkpoint,
            context,
        )
    return timeout_envelope
```

FastMCP uses AnyIO cancellation scopes. Shielded cleanup is required so the
same cancellation cannot interrupt process-tree termination or checkpoint
writing.

- [ ] **Step 3: Pass child deadlines through ToolBroker**

For each action:

```python
child = ExecutionContext(
    correlation_id=parent.correlation_id,
    workflow_slug=parent.workflow_slug,
    action_id=action["action_id"],
    attempt=action["attempt"],
    idempotency_key=action["idempotency_key"],
    token=parent.token,
    deadline=parent.deadline.child(action_timeout),
    event_sink=parent.event_sink,
)
```

Nested retries must use `child.deadline.remaining()` and cannot create a fresh
full timeout.

- [ ] **Step 4: Persist cancellation and checkpoint**

On cancellation:

```python
kernel.record_action_event(
    slug,
    "action.cancelled",
    {
        **action,
        "status": "cancelled",
        "reason": token.reason,
    },
)
kernel.checkpoint(slug, source_session=correlation_id)
```

- [ ] **Step 5: Run cancellation tests**

```powershell
python -m pytest -q `
  tests/test_mcp_transport.py `
  tests/test_mcp_process_cancellation.py `
  tests/test_execution_context.py `
  tests/test_process_supervisor.py -k "cancel or deadline or cleanup"
```

Expected: pass and leave no active process records.

- [ ] **Step 6: Commit**

```powershell
git add `
  mcp_server.py `
  core/workflow/tool_broker.py `
  core/workflow/kernel.py `
  tests/test_mcp_transport.py `
  tests/test_mcp_process_cancellation.py `
  tests/test_execution_context.py `
  tests/test_process_supervisor.py
git commit -m "feat: propagate cancellation and total deadlines"
```

---

### Task 16: Record Process Identity, Bounded Output, and Resume Metadata

**Files:**
- Modify: `core/process_identity.py`
- Modify: `core/process_supervisor.py`
- Modify: `core/workflow/kernel.py`
- Modify: `core/workflow/tool_broker.py`
- Modify: `tests/test_process_supervisor.py`
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Add identity and checkpoint assertions**

Require:

```python
assert result["identity"]["resolved_path"]
assert result["identity"]["version_output"]
assert result["stdout"]["retained_bytes"] <= max_output_bytes
assert result["stdout"]["total_bytes"] > result["stdout"]["retained_bytes"]
assert checkpoint["process"]["termination_reason"] == "workflow_deadline"
```

- [ ] **Step 2: Finalize executable identity before launch**

Implement:

```python
resolved = shutil.which(argv[0]) or str(Path(argv[0]).resolve())
identity = {
    "requested": argv[0],
    "resolved_path": resolved,
    "sha256": hash_file(resolved) if Path(resolved).is_file() else "",
    "version_args": list(version_args),
    "version_output": bounded_version_probe(resolved, version_args),
}
```

Place resolution, hashing, and version normalization in
`core/process_identity.py`. The version probe uses the same supervisor with a
five-second child deadline, `max_output_bytes=64 * 1024`, and
`capture_identity=False` to prevent recursion.

- [ ] **Step 3: Emit process events through the context sink**

On start, bounded output milestones, and termination:

```python
event_sink(
    "process.started",
    {"pid": pid, "identity": identity, "action_id": action_id},
)
```

Output events contain byte counts and truncation state, not raw secrets.

- [ ] **Step 4: Store partial process metadata in checkpoints**

The checkpoint projection includes active or recently terminated process
metadata keyed by action ID. Resume never assumes that an old PID is alive; it
uses the action status and tool resume capability.

- [ ] **Step 5: Run tests**

```powershell
python -m pytest -q tests/test_process_supervisor.py tests/test_orchestrator.py -k "identity or output or checkpoint or resume"
```

Expected: pass.

- [ ] **Step 6: Commit**

```powershell
git add core/process_identity.py core/process_supervisor.py core/workflow/kernel.py core/workflow/tool_broker.py tests/test_process_supervisor.py tests/test_orchestrator.py
git commit -m "feat: persist supervised process metadata"
```

---

## Final Verification and Delivery

### Task 17: Run Full Gates, Update Documentation, and Close the Case

**Files:**
- Modify: `pyproject.toml`
- Modify: `.gitignore`
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `TOOLS.md`
- Create: `D:\Open-tgtylab\exports\evidence\hunter-skill\unified-proof-engine-p0-p2-verification.json`
- Create: `D:\Open-tgtylab\exports\notes\hunter-unified-proof-engine-20260715.md`
- Create: `D:\Open-tgtylab\exports\reports\hunter-unified-proof-engine-20260715.md`
- Modify: `D:\Open-tgtylab\cases\hunter-skill\state.json`

- [ ] **Step 1: Close dependency and runtime-artifact gates**

Add explicit test dependencies:

```toml
[project.optional-dependencies]
test = [
  "pytest>=8",
  "pytest-asyncio>=0.23",
]
stealth = ["curl_cffi>=0.6.0"]
```

Add:

```gitignore
sessions/browser/
sessions/scans/
evidence/tool_output/
```

Do not delete committed evidence or reports.

- [ ] **Step 2: Run P0 acceptance tests**

```powershell
python -m pytest -q tests/test_proof_engine_p0.py
```

Expected: all pass:

- explicit reasoner actions execute;
- empty reasoner preserves general coverage;
- HTTP 200 plus `vulnerable=false` is not technique success;
- baseline SQL errors are not confirmed;
- phases, modules, and budget change actual execution.

- [ ] **Step 3: Run P1 gates**

```powershell
python -m pytest -q `
  tests/test_action_planner.py `
  tests/test_evidence_pipeline.py `
  tests/test_tool_broker.py `
  tests/test_workflow_kernel.py `
  tests/test_orchestrator.py `
  tests/test_orchestrator_runner.py
```

Expected: pass.

- [ ] **Step 4: Run P2 gates**

```powershell
python -m pytest -q `
  tests/test_execution_context.py `
  tests/test_process_supervisor.py `
  tests/test_process_supervisor_windows.py `
  tests/test_process_supervisor_posix.py `
  tests/test_external_process_runner.py `
  tests/test_mcp_transport.py `
  tests/test_mcp_process_cancellation.py
```

Expected: pass and zero managed orphan processes.

- [ ] **Step 5: Stress cancellation and timeout cleanup**

Run the cancellation/timeout process fixture 100 times. If `pytest-repeat` is
not installed:

```powershell
1..100 | ForEach-Object {
  python -m pytest -q `
    tests/test_process_supervisor.py `
    -k 'cancel or timeout'
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
```

Expected:

- managed orphan process count: 0;
- registry empty after every iteration;
- cancellation-to-process-disappearance p99 below one second;
- retained stdout and stderr remain within their configured bounds.

- [ ] **Step 6: Run the complete suite**

```powershell
python -m pytest -q
```

Expected: all tests pass. No exclusions are allowed for the five P0 acceptance
groups, entry-point parity, cancellation, process-tree cleanup, or registry
contract.

- [ ] **Step 7: Run static and contract checks**

```powershell
python -m py_compile `
  mcp_server.py `
  core/unified_scanner.py `
  core/workflow/action_planner.py `
  core/workflow/tool_broker.py `
  core/evidence/normalizer.py `
  core/execution_context.py `
  core/process_identity.py `
  core/process_supervisor.py `
  core/windows_job.py

python -c "import json, asyncio, mcp_server; print(asyncio.run(mcp_server.hunter_contract_check()))"
python -c "import asyncio, mcp_server; print(asyncio.run(mcp_server.hunter_doctor()))"
git diff --check
```

Expected:

- compilation succeeds;
- contract reports exactly 113 Hunter core tools and no missing tools;
- optional `re_*` tools are reported as extensions;
- doctor reports Web/API readiness independently from missing reverse tools;
- no whitespace errors.

- [ ] **Step 8: Update docs**

Document:

```text
WorkflowKernel event log is authoritative.
PatternEngine creates candidates only.
VerdictEngine alone creates verified findings.
TechniqueMemory success means VERIFIED, not HTTP transport success.
All four high-level entry points share one proof engine.
External CLI execution is cancellable, deadline-aware, bounded, and resumable.
```

- [ ] **Step 9: Write verification evidence, note, and report**

The JSON evidence artifact records exact commands, pass counts, duration,
contract counts, process cleanup metrics, the golden workflow trace, and
artifact hashes. The note summarizes those results and remaining P3–P4 work.

The report includes:

1. architecture before/after;
2. the four corrected Critical gaps;
3. compatibility behavior;
4. P0–P2 acceptance table;
5. benchmark and process-cleanup results;
6. deferred P3 tool-surface and HunterBench work.

- [ ] **Step 10: Update case state**

Set:

```json
{
  "status": "unified_proof_engine_p0_p2_verified",
  "next_steps": [
    "Implement P3 progressive core/web/reverse/full tool profiles without deleting atomic capability.",
    "Build HunterBench positive/negative end-to-end proof corpus.",
    "Add source-aware white-box candidate generation with dynamic proof correlation."
  ]
}
```

Append findings and output paths without deleting historical state.

- [ ] **Step 11: Commit final documentation and case state**

```powershell
git add pyproject.toml .gitignore SKILL.md README.md TOOLS.md
git commit -m "docs: document unified proof engine"

git -C D:\Open-tgtylab add `
  cases/hunter-skill/state.json `
  exports/evidence/hunter-skill/unified-proof-engine-p0-p2-verification.json `
  exports/notes/hunter-unified-proof-engine-20260715.md `
  exports/reports/hunter-unified-proof-engine-20260715.md
git -C D:\Open-tgtylab commit -m "docs: record hunter proof engine verification"
```

If `D:\Open-tgtylab` is not a Git repository in the active installation, save
the four workspace artifacts but omit the second commit.

- [ ] **Step 12: Verify final status**

```powershell
git status --short
git log -10 --oneline --decorate
```

Expected: source changes are committed. Only intentionally untracked runtime
session artifacts may remain.

---

## Plan Completion Criteria

The implementation is complete only when all of these statements are backed
by passing tests and persisted evidence:

1. Every explicit allowlisted reasoner action executes when policy and an
   executor permit it.
2. Reasoning augments general attack-surface coverage and never replaces it.
3. Requested phases, modules, approvals, and budgets affect actual execution.
4. `VerdictEngine` is the sole path to `confirmed`.
5. Findings reference only their own verified evidence.
6. HTTP status and process exit are not treated as vulnerability success.
7. TechniqueMemory learns confirmed effectiveness only after verdict.
8. All high-level MCP entry points use one workflow event/state path.
9. Completed idempotency keys are not executed or charged twice.
10. MCP cancellation and total deadlines terminate the full managed process
    tree.
11. Output is bounded while total byte counts and partial artifacts remain
    auditable.
12. Workflow checkpoints reconstruct the first incomplete action.
13. Core and extension tool inventories are explicit and compatible.
14. The full test suite, contract check, doctor, compilation, and diff checks
    pass.
