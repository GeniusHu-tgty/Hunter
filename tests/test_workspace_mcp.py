
import asyncio
import json

import mcp_server


NEW_TOOLS = {
    "hunter_workspace_health", "hunter_case_open", "hunter_case_status",
    "hunter_case_update", "hunter_case_next_steps", "hunter_project_kb_search",
    "hunter_project_kb_read", "hunter_evidence_save", "hunter_note_write",
    "hunter_report_publish", "hunter_workspace_recommend",
}


def test_workspace_tools_are_registered_without_losing_legacy_tools():
    functions = {name for name, value in vars(mcp_server).items() if name.startswith("hunter_") and callable(value)}
    assert NEW_TOOLS <= functions
    legacy = {
        "hunter_scan", "hunter_recon", "hunter_vuln_scan", "hunter_auto_sqli",
        "hunter_auto_xss", "hunter_healthcheck", "hunter_capabilities",
        "hunter_recommend_next", "hunter_kb_search", "hunter_burp_repeater",
        "hunter_report",
    }
    assert legacy <= functions


def test_health_capabilities_and_recommend_expose_workspace(monkeypatch, tmp_path):
    root = tmp_path / "Open-tgtylab"
    (root / "cases" / "demo").mkdir(parents=True)
    (root / "kb" / "general" / "techniques").mkdir(parents=True)
    (root / "exports" / "notes").mkdir(parents=True)
    (root / "exports" / "reports").mkdir(parents=True)
    (root / "cases" / "demo" / "state.json").write_text(json.dumps({"slug":"demo","next_steps":["proof"]}), encoding="utf-8")
    (root / "kb" / "general" / "techniques" / "jwt.md").write_text("jwt token proof", encoding="utf-8")
    monkeypatch.setenv("OPEN_TGTYLAB_ROOT", str(root))
    mcp_server._reset_workspace_adapter()

    health = json.loads(asyncio.run(mcp_server.hunter_healthcheck()))
    assert health["workspace"]["available"] is True
    caps = json.loads(asyncio.run(mcp_server.hunter_capabilities()))
    assert caps["tools"]["hunter_case_open"]["available"] is True
    rec = json.loads(asyncio.run(mcp_server.hunter_recommend_next(signals=["jwt"], finding="token", case_slug="demo")))
    assert rec["workspace"]["case_next_steps"] == ["proof"]
