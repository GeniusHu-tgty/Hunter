
import asyncio
import json

import mcp_server


def run(coro):
    return asyncio.run(coro)


def load(text):
    return json.loads(text)


def test_root_mcp_exposes_hunter_tools_wrappers():
    expected = [
        "hunter_kb_list",
        "hunter_kb_search",
        "hunter_kb_read",
        "hunter_kb_recommend",
        "hunter_burp_bridge",
        "hunter_burp_repeater",
        "hunter_burp_proxy_search",
        "hunter_burp_scanner_issues",
        "hunter_burp_collaborator_workflow",
    ]
    missing = [name for name in expected if not hasattr(mcp_server, name)]
    assert missing == []


def test_root_mcp_kb_search_and_burp_repeater_return_json():
    search = load(run(mcp_server.hunter_kb_search("ssrf collaborator metadata", 3)))
    assert search["status"] == "ok"
    assert search["tool"] == "hunter_kb_search"
    assert search["data"]["returned"] <= 3

    repeater = load(run(mcp_server.hunter_burp_repeater(
        "https://example.test/path?q=1",
        "GET",
        {"Accept": "application/json"},
        "",
        "Hunter proof",
        True,
    )))
    assert repeater["status"] == "ok"
    assert repeater["data"]["action"]["tool"] == "create_repeater_tab_http2"


def test_root_healthcheck_and_capabilities_include_v81_tools():
    health = load(run(mcp_server.hunter_healthcheck()))
    registered = health["mcp_tools"]["registered"]
    assert "hunter_kb_search" in registered
    assert "hunter_burp_repeater" in registered
    assert health["hunter_tools"]["tool_style"] == "reverse_lab_tools-compatible"

    caps = load(run(mcp_server.hunter_capabilities()))
    assert caps["tools"]["hunter_kb_search"]["category"] == "kb"
    assert caps["tools"]["hunter_burp_repeater"]["category"] == "burp-bridge"
    assert caps["hunter_tools"]["server_name"] == "hunter_tools"


def test_standalone_hunter_tools_mcp_module_exposes_same_wrappers_as_dicts():
    import hunter_tools_mcp

    assert hasattr(hunter_tools_mcp, "hunter_kb_search")
    result = run(hunter_tools_mcp.hunter_kb_search("jwt", 2))
    assert isinstance(result, dict)
    assert result["status"] == "ok"
    assert result["data"]["returned"] <= 2

    bridge = run(hunter_tools_mcp.hunter_burp_proxy_search("token|authorization", 10, 0))
    assert isinstance(bridge, dict)
    assert bridge["status"] == "ok"
    assert bridge["data"]["action"]["tool"] == "get_proxy_http_history_regex"


def test_recommend_next_is_enriched_with_kb_and_burp_actions():
    result = load(run(mcp_server.hunter_recommend_next(
        target="https://example.test/api/user/1",
        signals=["jwt", "idor"],
        finding="Authorization token and userId object access",
    )))
    assert "hunter_tools" in result
    assert result["hunter_tools"]["kb_hits"]
    assert result["hunter_tools"]["burp_actions"]
