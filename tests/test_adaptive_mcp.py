import asyncio
import json
import mcp_server

TOOLS = {
    "hunter_fast_scan", "hunter_scan_plan", "hunter_scan_benchmark",
    "hunter_cache_status", "hunter_cache_clear",
}


def test_adaptive_tools_registered_and_contracted():
    registered = {name for name, value in vars(mcp_server).items() if name.startswith("hunter_") and callable(value)}
    assert TOOLS <= registered
    contract = json.loads(asyncio.run(mcp_server.hunter_contract_check()))
    assert TOOLS <= set(contract["data"]["required_tools"])
    assert contract["data"]["registered_tool_count"] >= 65


def test_adaptive_plan_and_cache_smoke():
    plan = json.loads(asyncio.run(mcp_server.hunter_scan_plan("https://example.test", "fast")))
    assert plan["status"] == "ok"
    assert plan["data"]["profile"]["name"] == "fast"
    status = json.loads(asyncio.run(mcp_server.hunter_cache_status()))
    assert status["status"] == "ok"
    caps = json.loads(asyncio.run(mcp_server.hunter_capabilities()))
    assert TOOLS <= set(caps["tools"])
