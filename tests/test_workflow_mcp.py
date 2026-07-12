import asyncio
import json
import mcp_server

TOOLS = {
    "hunter_workflow_create", "hunter_workflow_open", "hunter_workflow_status", "hunter_workflow_run",
    "hunter_workflow_route", "hunter_workflow_plan", "hunter_workflow_transition",
    "hunter_workflow_checkpoint", "hunter_workflow_resume", "hunter_workflow_policy",
    "hunter_hypothesis_add", "hunter_evidence_register", "hunter_finding_promote",
    "hunter_backend_status", "hunter_lane_catalog",
}


def test_workflow_tools_registered_and_contracted():
    registered = {name for name, value in vars(mcp_server).items() if name.startswith("hunter_") and callable(value)}
    assert TOOLS <= registered
    contract = json.loads(asyncio.run(mcp_server.hunter_contract_check()))
    assert TOOLS <= set(contract["data"]["required_tools"])


def test_workflow_mcp_smoke(tmp_path):
    mcp_server._reset_workspace_adapter(tmp_path)
    created = json.loads(asyncio.run(mcp_server.hunter_workflow_create(
        "mcp-case", "recover flag", inputs=[{"path": "sample.exe"}], mode="autopilot"
    )))
    assert created["status"] == "ok"
    assert created["data"]["state"]["lane"] == "pe"
    plan = json.loads(asyncio.run(mcp_server.hunter_workflow_plan("mcp-case", max_actions=2)))
    assert plan["status"] == "ok"
    assert plan["data"]["actions"]
    lanes = json.loads(asyncio.run(mcp_server.hunter_lane_catalog()))
    assert {"pe", "apk", "javascript", "mixed"} <= set(lanes["data"]["lanes"])


def test_reset_workspace_adapter_rebinds_workflow_root(tmp_path):
    first=tmp_path/"one"; second=tmp_path/"two"
    for root in (first,second):
        (root/"cases").mkdir(parents=True); (root/"kb").mkdir(); (root/"exports").mkdir()
    mcp_server._reset_workspace_adapter(first)
    one=json.loads(asyncio.run(mcp_server.hunter_workflow_create("same","one",inputs=[])))
    mcp_server._reset_workspace_adapter(second)
    two=json.loads(asyncio.run(mcp_server.hunter_workflow_create("same","two",inputs=[])))
    assert one["status"]==two["status"]=="ok"
    assert (first/"cases"/"same"/"workflow.json").exists()
    assert (second/"cases"/"same"/"workflow.json").exists()
