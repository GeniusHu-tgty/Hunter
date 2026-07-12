import asyncio
import json
import mcp_server

TOOLS = {"hunter_doctor", "hunter_config_audit", "hunter_runtime_status", "hunter_contract_check"}

def test_integration_v2_tools_registered():
    functions = {n for n, v in vars(mcp_server).items() if n.startswith("hunter_") and callable(v)}
    assert TOOLS <= functions

def test_integration_v2_mcp_smoke():
    contract = json.loads(asyncio.run(mcp_server.hunter_contract_check()))
    assert contract["status"] == "ok"
    assert contract["data"]["server_name"] == "hunter_tools"
    caps = json.loads(asyncio.run(mcp_server.hunter_capabilities()))
    assert TOOLS <= set(caps["tools"])
    health = json.loads(asyncio.run(mcp_server.hunter_healthcheck()))
    assert health["integration_v2"]["contract"]["status"] == "ok"
