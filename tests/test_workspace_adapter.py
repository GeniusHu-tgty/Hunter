
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
