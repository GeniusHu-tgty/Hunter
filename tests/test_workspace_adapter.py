
import json
from pathlib import Path

import pytest

from core.workspace_adapter import OpenTgtyLabWorkspaceAdapter


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "Open-tgtylab"
    (root / "cases" / "demo").mkdir(parents=True)
    (root / "kb" / "ctf-website" / "techniques" / "02-auth").mkdir(parents=True)
    (root / "kb" / "general" / "techniques").mkdir(parents=True)
    (root / "exports" / "notes").mkdir(parents=True)
    (root / "exports" / "reports").mkdir(parents=True)
    (root / "cases" / "demo" / "state.json").write_text(json.dumps({
        "slug": "demo", "status": "active", "target": "https://example.test",
        "next_steps": ["inspect auth", "collect proof"]
    }), encoding="utf-8")
    (root / "kb" / "ctf-website" / "techniques" / "02-auth" / "jwt.md").write_text(
        "# JWT\nTest alg none and authorization boundaries.", encoding="utf-8")
    (root / "kb" / "general" / "techniques" / "evidence.md").write_text(
        "# Evidence\nSave reproducible request and response proof.", encoding="utf-8")
    monkeypatch.setenv("OPEN_TGTYLAB_ROOT", str(root))
    return root


def test_discovers_workspace_from_env(workspace):
    adapter = OpenTgtyLabWorkspaceAdapter()
    assert adapter.root == workspace.resolve()
    assert adapter.health()["data"]["available"] is True


def test_case_open_status_next_steps_and_controlled_update(workspace):
    adapter = OpenTgtyLabWorkspaceAdapter()
    opened = adapter.case_open("demo")
    assert opened["data"]["state"]["status"] == "active"
    assert adapter.case_status("demo")["data"]["status"] == "active"
    assert adapter.case_next_steps("demo")["data"]["next_steps"] == ["inspect auth", "collect proof"]

    updated = adapter.case_update("demo", {"status": "proof-collected", "next_steps": ["write report"]})
    assert updated["status"] == "ok"
    state = json.loads((workspace / "cases" / "demo" / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "proof-collected"
    assert state["next_steps"] == ["write report"]
    assert "updated_at" in state

    blocked = adapter.case_update("../escape", {"status": "bad"})
    assert blocked["status"] == "error"


def test_project_kb_search_read_and_path_safety(workspace):
    adapter = OpenTgtyLabWorkspaceAdapter()
    result = adapter.kb_search("jwt authorization", board="ctf-website", limit=5)
    assert result["status"] == "ok"
    assert result["data"]["results"][0]["path"].endswith("02-auth/jwt.md")

    read = adapter.kb_read("02-auth/jwt.md", board="ctf-website")
    assert "authorization boundaries" in read["data"]["content"]
    assert adapter.kb_read("../../AGENTS.md", board="ctf-website")["status"] == "error"
    assert adapter.kb_search("jwt", board="not-real")["status"] == "error"




def test_project_kb_search_auto_routes_across_boards(workspace):
    result = OpenTgtyLabWorkspaceAdapter().kb_search(
        "jwt authorization",
        board="auto",
        limit=5,
    )

    assert result["status"] == "ok"
    assert result["data"]["results"][0]["board"] == "ctf-website"
    assert result["data"]["results"][0]["path"].endswith("02-auth/jwt.md")
    assert result["next_actions"][0]["arguments"]["board"] == "ctf-website"


def test_project_kb_search_prefers_query_coverage_over_repeated_generic_terms(workspace):
    root = workspace / "kb" / "general" / "techniques"
    (root / "reliability.md").write_text(
        "# MCP Reliability\nDiagnostics configuration runtime timeout subprocess evidence quality.",
        encoding="utf-8",
    )
    (root / "generic.md").write_text(
        "# Generic\n" + "tool " * 80,
        encoding="utf-8",
    )

    result = OpenTgtyLabWorkspaceAdapter().kb_search(
        "MCP tool reliability diagnostics configuration runtime timeout subprocess evidence quality",
        board="general",
        limit=5,
    )

    assert result["data"]["results"][0]["path"] == "reliability.md"
    assert result["data"]["results"][0]["matched_tokens"] >= 8
    assert result["data"]["results"][0]["coverage"] > 0.8


def test_artifact_routes_write_inside_workspace(workspace):
    adapter = OpenTgtyLabWorkspaceAdapter()
    evidence = adapter.evidence_save("demo", "idor/request.json", '{"id":2}')
    note = adapter.note_write("demo-analysis.md", "# Analysis")
    report = adapter.report_publish("demo-report.md", "# Report")
    assert Path(evidence["data"]["path"]).read_text(encoding="utf-8") == '{"id":2}'
    assert Path(note["data"]["path"]).parent == workspace / "exports" / "notes"
    assert Path(report["data"]["path"]).parent == workspace / "exports" / "reports"
    assert adapter.evidence_save("../bad", "x", "x")["status"] == "error"
    assert adapter.note_write("../bad.md", "x")["status"] == "error"


def test_workspace_recommend_combines_case_project_kb_and_protocol(workspace):
    adapter = OpenTgtyLabWorkspaceAdapter()
    result = adapter.recommend(case_slug="demo", signals=["jwt", "authorization"], finding="Bearer token boundary")
    assert result["status"] == "ok"
    data = result["data"]
    assert data["case"]["slug"] == "demo"
    assert data["case_next_steps"] == ["inspect auth", "collect proof"]
    assert data["project_kb_hits"]
    assert data["protocol"]["http_priority"][0] == "Burp send_http2_request"
    assert "hunter_auto_jwt" in [x["tool"] for x in data["tool_recommendations"]]

def test_case_state_accepts_utf8_bom(workspace):
    state_path = workspace / "cases" / "demo" / "state.json"
    original = state_path.read_text(encoding="utf-8")
    state_path.write_text(original, encoding="utf-8-sig")
    adapter = OpenTgtyLabWorkspaceAdapter()
    opened = adapter.case_open("demo")
    assert opened["status"] == "ok"
    assert opened["data"]["state"]["slug"] == "demo"
    updated = adapter.case_update("demo", {"status": "bom-compatible"})
    assert updated["status"] == "ok"

def test_workspace_discovery_has_no_fixed_windows_drive(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in ("OPEN_TGTYLAB_ROOT", "OPEN_TGTYLAB_WORKSPACE", "TGTYLAB_ROOT"):
        monkeypatch.delenv(name, raising=False)
    from core.workspace_adapter import OpenTgtyLabWorkspaceAdapter
    root = OpenTgtyLabWorkspaceAdapter.discover_root()
    assert root == tmp_path.resolve()



def test_workspace_recommend_routes_chinese_access_control_signals(workspace):
    result = OpenTgtyLabWorkspaceAdapter().recommend(
        signals=["\u8d8a\u6743", "\u6c34\u5e73\u8d8a\u6743"],
        finding="cross-user object access",
    )
    tools = [item["tool"] for item in result["data"]["tool_recommendations"]]
    assert "hunter_auto_idor" in tools
    assert "hunter_auto_access_control" in tools
