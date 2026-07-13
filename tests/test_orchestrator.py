import asyncio
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import mcp_server
import pytest

from core.workflow.kernel import (
    OrchestratorInterrupted,
    UnifiedOrchestrator,
    WorkflowKernel,
)


STAGES = (
    "memory",
    "recon",
    "attack_surface",
    "attack_execution",
    "vulnerability_confirmation",
    "evidence_learning",
    "report",
)


def _workflow(kernel, slug="orchestrator-case", mode="autopilot"):
    kernel.create(
        slug,
        "authorized unified orchestration test",
        inputs=[{"type": "url", "value": "https://example.test"}],
        mode=mode,
        success_conditions=["confirmed-finding"],
        proof_types=["request-response"],
    )
    return slug


def _adapters(calls, pause_once=False):
    paused = {"value": False}

    def adapter(stage, result):
        def run(context):
            calls.append(stage)
            if pause_once and stage == "attack_execution" and not paused["value"]:
                paused["value"] = True
                raise OrchestratorInterrupted("test interruption")
            return result

        return run

    return {
        "memory": adapter(
            "memory",
            {
                "memo": {
                    "target_seen": True,
                    "best_techniques": ["case-variation"],
                    "fingerprints": {"waf": "Cloudflare"},
                }
            },
        ),
        "recon": adapter(
            "recon",
            {
                "target_profile": {
                    "target_url": "https://example.test",
                    "fingerprints": {"waf": "Cloudflare", "framework": "Django"},
                    "api_endpoints": ["/api/search"],
                }
            },
        ),
        "attack_surface": adapter(
            "attack_surface",
            {"attack_queue": [{"kind": "sqli", "target": "/api/search"}]},
        ),
        "attack_execution": adapter(
            "attack_execution",
            {
                "attempts": [{"technique": "case-variation", "success": True}],
                "handoffs": [{"execution": "deferred", "tool": "hunter_auto_sqli"}],
            },
        ),
        "vulnerability_confirmation": adapter(
            "vulnerability_confirmation",
            {
                "findings": [
                    {
                        "title": "SQL injection",
                        "status": "confirmed",
                        "severity": "high",
                        "satisfies": ["confirmed-finding"],
                    }
                ]
            },
        ),
        "evidence_learning": adapter(
            "evidence_learning",
            {
                "evidence": [{"summary": "request-response pair"}],
                "learning_updates": [{"technique": "case-variation", "success": True}],
            },
        ),
        "report": adapter(
            "report",
            {"report_path": "reports/orchestrator-case.md"},
        ),
    }


def test_unified_orchestrator_runs_all_stages_and_persists_progress(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    calls = []
    orchestrator = UnifiedOrchestrator(kernel, adapters=_adapters(calls))

    result = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["all"],
        policy="standard",
    )

    assert result["status"] == "completed"
    assert calls == list(STAGES)
    assert set(result["stage_results"]) == set(STAGES)
    assert result["memo"]["fingerprints"]["waf"] == "Cloudflare"
    assert result["target_profile"]["api_endpoints"] == ["/api/search"]
    assert result["attack_queue"][0]["kind"] == "sqli"
    assert result["findings"][0]["severity"] == "high"
    assert result["report_path"].endswith("reports/orchestrator-case.md")
    assert result["checkpoints_created"] == len(STAGES)

    state = kernel.materialize(slug)
    assert state["orchestrator"]["current_stage"] == "complete"
    assert state["orchestrator"]["stage_status"]["report"] == "completed"
    assert state["metrics"]["checkpoints"] >= len(STAGES)
    assert len(state["evidence"]) == 1
    assert state["findings"][0]["title"] == "SQL injection"
    status = kernel.status(slug)
    assert status["orchestrator"]["status"] == "completed"
    assert status["stage_results"]["report"]["report_path"].endswith(
        "reports/orchestrator-case.md"
    )


def test_orchestrator_interruption_creates_checkpoint_and_resume_continues(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    calls = []
    adapters = _adapters(calls, pause_once=True)
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    interrupted = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["web"],
        policy="standard",
    )

    assert interrupted["status"] == "interrupted"
    assert interrupted["interrupted_stage"] == "attack_execution"
    assert interrupted["checkpoint_id"]
    assert calls == list(STAGES[:3]) + ["attack_execution"]

    resumed = orchestrator.resume(slug, target_url="https://example.test")

    assert resumed["status"] == "completed"
    assert resumed["resumed_from"] == "attack_execution"
    assert calls == list(STAGES[:3]) + ["attack_execution"] + list(STAGES[3:])


def test_concurrent_orchestrators_execute_each_stage_once(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    calls = []
    adapters = _adapters(calls)

    for stage, adapter in list(adapters.items()):
        def slow_adapter(context, _adapter=adapter):
            time.sleep(0.02)
            return _adapter(context)

        adapters[stage] = slow_adapter

    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    def run():
        return orchestrator.orchestrate(
            slug,
            target_url="https://example.test",
            modules=["web"],
            policy="standard",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run), pool.submit(run)]
        results = [future.result() for future in futures]

    assert all(result["status"] == "completed" for result in results)
    assert calls == list(STAGES)


def test_interactive_policy_pauses_before_high_impact_actions(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")

    adapters = _adapters([])
    original = adapters["attack_execution"]
    adapters["attack_execution"] = lambda context: {
        "confirmation_required": True,
        "reason": "confirmed command execution requires analyst approval",
        "actions": [{"tool": "hunter_post_exploit", "execution": "deferred"}],
    }
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    result = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["web"],
        policy="standard",
    )

    assert result["status"] == "awaiting_confirmation"
    assert result["confirmation_required"][0]["tool"] == "hunter_post_exploit"
    assert result["current_stage"] == "attack_execution"
    assert original is not None
    pending = result["confirmation_required"][0]

    approved = orchestrator.resume(
        slug,
        target_url="https://example.test",
        approval={
            "stage": "attack_execution",
            "approved": True,
            "decision_id": "decision-001",
            "confirmation_id": pending["confirmation_id"],
            "confirmation_digest": pending["confirmation_digest"],
            "scope": pending["scope"],
        },
    )
    assert approved["status"] == "completed"


def _confirmation_adapters(marker_default="A"):
    adapters = _adapters([])

    def attack_execution(context):
        marker = context.get("observations", {}).get(
            "marker", marker_default
        )
        return {
            "confirmation_required": [
                {
                    "tool": "hunter_post_exploit",
                    "execution": "deferred",
                    "arguments": {"finding": marker},
                    "scope": {"finding": marker},
                }
            ],
            "reason": "analyst approval required",
        }

    adapters["attack_execution"] = attack_execution
    return adapters


def test_approval_requires_an_existing_pending_confirmation(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )

    with pytest.raises(ValueError, match="pending confirmation"):
        orchestrator.orchestrate(
            slug,
            target_url="https://example.test",
            approval={
                "stage": "attack_execution",
                "approved": True,
                "decision_id": "premature",
                "confirmation_id": "confirm-missing",
                "confirmation_digest": "0" * 64,
                "scope": {"finding": "A"},
            },
        )


def test_approval_for_action_a_does_not_authorize_changed_action_b(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )
    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )
    pending = first["confirmation_required"][0]

    changed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        observations={"marker": "B"},
        approval={
            "stage": "attack_execution",
            "approved": True,
            "decision_id": "approve-a",
            "confirmation_id": pending["confirmation_id"],
            "confirmation_digest": pending["confirmation_digest"],
            "scope": pending["scope"],
        },
    )

    assert changed["status"] == "awaiting_confirmation"
    assert changed["confirmation_required"][0]["arguments"]["finding"] == "B"


def test_approval_scope_must_match_pending_confirmation(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )
    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )
    pending = first["confirmation_required"][0]

    with pytest.raises(ValueError, match="scope"):
        orchestrator.resume(
            slug,
            target_url="https://example.test",
            approval={
                "stage": "attack_execution",
                "approved": True,
                "decision_id": "bad-scope",
                "confirmation_id": pending["confirmation_id"],
                "confirmation_digest": pending["confirmation_digest"],
                "scope": {"finding": "B"},
            },
        )


def test_exact_approval_is_consumed_after_stage_completion(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )
    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )
    pending = first["confirmation_required"][0]

    completed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        approval={
            "stage": "attack_execution",
            "approved": True,
            "decision_id": "exact-approval",
            "confirmation_id": pending["confirmation_id"],
            "confirmation_digest": pending["confirmation_digest"],
            "scope": pending["scope"],
        },
    )

    assert completed["status"] == "completed"
    approval = kernel.materialize(slug)["orchestrator"]["approvals"][0]
    assert approval["consumed"] is True
    assert approval["consumed_at"]


def test_default_high_impact_confirmation_is_required_in_autopilot(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="autopilot")
    orchestrator = UnifiedOrchestrator(kernel)
    state = kernel.materialize(slug)
    context = orchestrator._context(
        state,
        "https://example.test",
        ["web"],
        orchestrator._profile("standard"),
    )
    context["observations"] = {
        "responses": ["uid=1000(www-data) gid=1000(www-data)"]
    }

    result = orchestrator._stage_confirmation(context)

    assert result["confirmation_required"]
    assert result["confirmation_required"][0]["tool"] == "hunter_post_exploit"


def test_orchestrator_loads_memory_and_persists_learning_updates(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    adapters = _adapters([])
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    result = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["api", "js"],
        policy="fast",
    )

    assert result["memo"]["target_seen"] is True
    assert result["learning_updates"][0]["technique"] == "case-variation"
    state = kernel.materialize(slug)
    assert state["learning_updates"][0]["success"] is True
    assert state["orchestrator"]["modules"] == ["api", "js"]


def test_evidence_registration_failure_remains_resumable_and_idempotent(
    tmp_path,
):
    class FailingEvidenceKernel(WorkflowKernel):
        def __init__(self, root):
            super().__init__(root)
            self.failures_remaining = 1

        def register_evidence(self, *args, **kwargs):
            if self.failures_remaining:
                self.failures_remaining -= 1
                raise OSError("evidence store unavailable")
            return super().register_evidence(*args, **kwargs)

    kernel = FailingEvidenceKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_adapters([])
    )

    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )

    assert first["status"] == "blocked"
    assert first["blocked_stage"] == "evidence_learning"
    state = kernel.materialize(slug)
    assert state["orchestrator"]["stage_status"]["evidence_learning"] != (
        "completed"
    )
    assert state["evidence"] == []
    assert state["findings"] == []

    resumed = orchestrator.resume(
        slug, target_url="https://example.test"
    )

    assert resumed["status"] == "completed"
    state = kernel.materialize(slug)
    assert len(state["evidence"]) == 1
    assert len(state["findings"]) == 1


def test_auto_pentest_tool_runs_passive_default_orchestrator(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )

    result = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                "https://example.test",
                {"policy": "fast", "modules": ["web"]},
            )
        )
    )

    assert result["status"] in {"ok", "awaiting_confirmation"}
    assert result["data"]["target_url"] == "https://example.test"
    assert "stage_results" in result["data"]
    assert result["data"]["execution"] == "deferred"


def test_auto_pentest_updates_mode_when_resuming_existing_target(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    target = "https://mode.example.test"
    first = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target, {"mode": "interactive"}
            )
        )
    )
    second = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {"mode": "autopilot", "resume": True},
            )
        )
    )

    assert second["data"]["workflow_slug"] == first["data"]["workflow_slug"]
    state = WorkflowKernel(tmp_path).materialize(
        second["data"]["workflow_slug"]
    )
    assert state["policy"]["mode"] == "autopilot"


def test_auto_pentest_creates_new_generation_when_configuration_changes(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    target = "https://generation.example.test"
    observations = {
        "stage_results": {
            "attack_execution": {"attempts": [], "handoffs": []}
        }
    }
    first = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {
                    "mode": "autopilot",
                    "policy": "fast",
                    "modules": ["web"],
                    "observations": observations,
                },
            )
        )
    )
    second = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {
                    "mode": "autopilot",
                    "policy": "deep",
                    "modules": ["reverse"],
                    "observations": observations,
                },
            )
        )
    )

    assert first["data"]["status"] == "completed"
    assert second["data"]["status"] == "completed"
    assert second["data"]["workflow_slug"] != first["data"]["workflow_slug"]
    assert second["data"]["generation"]["number"] == 2


def test_auto_pentest_fresh_run_creates_new_generation(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    target = "https://fresh.example.test"
    first = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target, {"mode": "autopilot"}
            )
        )
    )
    second = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {
                    "mode": "autopilot",
                    "fresh_run": True,
                },
            )
        )
    )

    assert second["data"]["workflow_slug"] != first["data"]["workflow_slug"]
    assert second["data"]["generation"]["number"] == 2


def test_old_workflow_state_is_migrated_before_orchestrator_events(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    events_path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    event = json.loads(events_path.read_text(encoding="utf-8").strip())
    state = event["payload"]["state"]
    for key in (
        "orchestrator",
        "memo",
        "target_profile",
        "attack_surface",
        "attack_queue",
        "learning_updates",
        "report_path",
    ):
        state.pop(key, None)
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    event["event_hash"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    events_path.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")

    result = UnifiedOrchestrator(kernel, adapters=_adapters([])).orchestrate(
        slug,
        target_url="https://example.test",
        policy="fast",
    )

    assert result["status"] == "completed"
    assert kernel.materialize(slug)["orchestrator"]["current_stage"] == "complete"


def test_deferred_stage_waits_for_external_result_then_resume_consumes_it(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    adapters = _adapters([])
    adapters["attack_execution"] = lambda context: {
        "status": "deferred",
        "handoffs": [{"tool": "hunter_auto_sqli", "execution": "deferred"}],
    }
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    pending = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        policy="standard",
    )

    assert pending["status"] == "awaiting_external"
    assert pending["current_stage"] == "attack_execution"
    assert pending["stage_results"]["attack_execution"]["handoffs"]

    resumed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        observations={
            "stage_results": {
                "attack_execution": {
                    "status": "completed",
                    "attempts": [{"technique": "case-variation", "success": True}],
                    "handoffs": [],
                }
            }
        },
    )
    assert resumed["status"] == "completed"
    assert resumed["learning_updates"][0]["technique"] == "case-variation"


def test_checkpoint_resume_recovers_from_corrupt_event_tail(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel,
        adapters=_adapters([], pause_once=True),
    )
    interrupted = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        policy="standard",
    )
    events_path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    with events_path.open("a", encoding="utf-8") as handle:
        handle.write('{"broken":')

    resumed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        checkpoint_id=interrupted["checkpoint_id"],
    )

    assert resumed["status"] == "completed"
    assert json.loads(events_path.read_text(encoding="utf-8").splitlines()[-1])["type"] == "orchestrator.completed"
