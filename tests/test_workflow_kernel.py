import json
from pathlib import Path

import pytest

from core.workflow import WorkflowKernel
from core.workflow.backends import BackendRegistry
from core.workflow.models import WorkflowPolicy


def test_create_persists_v2_state_and_append_only_event(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    result = kernel.create("rev-1", objective="recover flag", inputs=[{"path": "challenge.exe"}], mode="autopilot")
    state = result["state"]
    assert state["schema_version"] == "2.0"
    assert state["lane"] == "pe"
    assert state["phase"] == "intake"
    assert state["policy"]["mode"] == "autopilot"
    events = (tmp_path / "cases" / "rev-1" / "workflow.events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(events) == 1
    assert json.loads(events[0])["type"] == "workflow.created"


def test_materializer_rebuilds_state_from_events(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("case-a", objective="inspect app", inputs=[{"path": "app.apk"}])
    kernel.add_hypothesis("case-a", "native library validates token", confidence=0.6)
    kernel.transition("case-a", "triage", deliverables={"objective": True, "artifact_inventory": True})
    rebuilt = kernel.materialize("case-a")
    assert rebuilt["phase"] == "triage"
    assert rebuilt["hypotheses"][0]["claim"] == "native library validates token"
    assert len(rebuilt["history"]) == 3


def test_lane_router_uses_strongest_signal_and_supports_mixed(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    assert kernel.route(inputs=[{"path": "a.exe"}])["primary_lane"] == "pe"
    assert kernel.route(inputs=[{"path": "a.apk"}])["primary_lane"] == "apk"
    assert kernel.route(inputs=[{"url": "https://x.test/app.js"}])["primary_lane"] == "javascript"
    mixed = kernel.route(inputs=[{"path": "a.apk"}, {"url": "https://x.test/api"}])
    assert mixed["primary_lane"] == "mixed"
    assert {"apk", "api"} <= set(mixed["secondary_lanes"])


def test_phase_gate_rejects_missing_deliverables(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("gate", objective="solve", inputs=[{"path": "a.exe"}])
    with pytest.raises(ValueError, match="missing deliverables"):
        kernel.transition("gate", "triage")
    state = kernel.transition("gate", "triage", deliverables={"objective": True, "artifact_inventory": True})["state"]
    assert state["phase"] == "triage"


def test_backend_registry_adapts_without_executing_reverse_tools():
    registry = BackendRegistry.default()
    pe = registry.resolve("pe")
    apk = registry.resolve("apk")
    js = registry.resolve("javascript")
    mixed = registry.resolve("mixed")
    assert pe[0]["server"] == "reverse_lab_tools"
    assert "triage_pe" in pe[0]["capabilities"]
    assert apk[0]["server"] == "reverse_lab_tools"
    assert js[0]["server"] == "jshook"
    assert {item["server"] for item in mixed} >= {"hunter_tools", "reverse_lab_tools", "jshook"}


def test_planner_is_budgeted_and_policy_aware(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("plan", objective="solve", inputs=[{"path": "a.apk"}], mode="interactive")
    plan = kernel.plan("plan", max_actions=2)
    assert len(plan["actions"]) <= 2
    assert plan["requires_confirmation"] is True
    assert all("estimated_cost" in action for action in plan["actions"])
    kernel.set_policy("plan", WorkflowPolicy(mode="autopilot", max_tool_calls=1))
    plan = kernel.plan("plan", max_actions=5)
    assert len(plan["actions"]) == 1
    assert plan["requires_confirmation"] is False


def test_checkpoint_and_resume_preserve_delta_and_dead_ends(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("resume", objective="solve", inputs=[{"url": "https://x.test"}])
    kernel.record_dead_end("resume", "sqli on id", signature="sqli:id:quote")
    checkpoint = kernel.checkpoint("resume", source_session="codex-1")
    assert Path(checkpoint["path"]).exists()
    resumed = kernel.resume("resume", checkpoint["checkpoint_id"])
    assert resumed["state"]["dead_ends"][0]["signature"] == "sqli:id:quote"
    assert resumed["resume_hint"]["objective"] == "solve"


def test_evidence_and_finding_lifecycle(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("proof", objective="prove", inputs=[{"url": "https://x.test"}])
    evidence = kernel.register_evidence("proof", summary="response differs", source="burp", path_or_url="evidence/r.json")
    finding = kernel.promote_finding("proof", title="IDOR", status="reproduced", evidence_ids=[evidence["evidence"]["id"]])
    assert finding["finding"]["status"] == "reproduced"
    with pytest.raises(ValueError, match="evidence"):
        kernel.promote_finding("proof", title="No proof", status="confirmed", evidence_ids=[])


def test_guided_policy_and_validation_retry_are_supported(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("guided", objective="solve", inputs=[{"url": "https://x.test"}], mode="guided")
    assert kernel.plan("guided")["requires_confirmation"] is False
    kernel.transition("guided", "triage", {"objective": True, "artifact_inventory": True})
    kernel.transition("guided", "map", {"triage_summary": True})
    kernel.transition("guided", "hypothesis", {"surface_map": True})
    kernel.transition("guided", "deep-analysis", {"active_hypothesis": True})
    kernel.transition("guided", "validation", {"analysis_result": True})
    state = kernel.transition("guided", "hypothesis", {"validation_failed": True})["state"]
    assert state["phase"] == "hypothesis"


def test_router_respects_magic_over_ambiguous_extension():
    kernel = WorkflowKernel(".")
    routed = kernel.route(inputs=[{"path": "sample.bin", "magic": "MZ"}])
    assert routed["primary_lane"] == "pe"
    assert routed["signals"][0]["source"] == "magic"


def test_all_catalog_lanes_have_backend_contracts():
    registry = BackendRegistry.default()
    for lane in ("source", "firmware", "script", "document", "protocol", "capture", "pwn", "crypto"):
        resolved = registry.resolve(lane)
        assert resolved, lane
        assert all(item["capabilities"] for item in resolved)


def test_proof_early_stop_marks_workflow_complete(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("early", objective="obtain proof", inputs=[{"url": "https://x.test"}], mode="autopilot")
    ev = kernel.register_evidence("early", "flag captured", "test")
    result = kernel.promote_finding("early", "CTF proof", "confirmed", [ev["evidence"]["id"]])
    assert result["state"]["status"] == "complete"
    assert kernel.plan("early")["actions"] == []


def test_autopilot_run_executes_native_actions_and_defers_external(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("run", objective="map api", inputs=[{"url": "https://x.test/api"}], mode="autopilot")
    calls=[]
    def execute(action):
        calls.append(action["tool"]); return {"status":"ok","summary":"signal","signals":["api"]}
    result=kernel.run("run", execute_native=execute, max_actions=2)
    assert len(calls)==2
    assert len(result["executed"])==2


def test_autopilot_run_returns_external_handoffs(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    kernel.create("handoff", objective="triage pe", inputs=[{"path":"a.exe"}], mode="autopilot")
    result=kernel.run("handoff", execute_native=lambda action: {}, max_actions=2)
    assert result["executed"]==[]
    assert result["handoffs"]
    assert result["handoffs"][0]["server"]=="reverse_lab_tools"


def test_mixed_plan_prioritizes_backend_diversity(tmp_path):
    kernel=WorkflowKernel(tmp_path)
    kernel.create("diverse", objective="solve mixed", inputs=[{"url":"https://x.test"},{"path":"a.exe"}], mode="autopilot")
    actions=kernel.plan("diverse", max_actions=4)["actions"]
    assert len({a["server"] for a in actions}) >= 2


def test_state_matches_open_tgtylab_v2_contract(tmp_path):
    state=WorkflowKernel(tmp_path).create("contract", "proof", [{"path":"a.exe"}], mode="guided")["state"]
    assert state["case"]["slug"]=="contract"
    assert state["objective"]["text"]=="proof"
    assert state["scope"]["targets"]==[{"path":"a.exe"}]
    assert state["policy"]["mode"]=="guided"


def test_event_matches_open_tgtylab_event_contract(tmp_path):
    kernel=WorkflowKernel(tmp_path); kernel.create("event-contract","proof",[])
    event=json.loads((tmp_path/"cases"/"event-contract"/"workflow.events.jsonl").read_text().splitlines()[0])
    assert event["schema_version"]=="1.0"
    assert event["workflow_id"].startswith("wf-")
    assert event["actor"]=="hunter_tools"
