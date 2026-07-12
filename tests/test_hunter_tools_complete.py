
import json
from pathlib import Path

import mcp_server


def registered_functions(module):
    return {
        name for name, value in vars(module).items()
        if name.startswith("hunter_") and callable(value)
    }


def test_complete_server_is_named_hunter_tools():
    assert mcp_server.mcp.name == "hunter_tools"


def test_complete_server_exposes_all_legacy_and_v81_tools():
    required = {
        "hunter_scan", "hunter_recon", "hunter_vuln_scan",
        "hunter_subdomain", "hunter_port_scan", "hunter_tech_detect",
        "hunter_dir_enum", "hunter_js_analyze",
        "hunter_auto_sqli", "hunter_auto_xss", "hunter_auto_ssrf",
        "hunter_auto_ssti", "hunter_auto_cmd", "hunter_auto_xxe",
        "hunter_auto_idor", "hunter_auto_csrf", "hunter_auto_cors",
        "hunter_auto_jwt", "hunter_auto_graphql", "hunter_auto_websocket",
        "hunter_auto_race", "hunter_auto_access_control", "hunter_unified_scan",
        "hunter_healthcheck", "hunter_capabilities", "hunter_recommend_next",
        "hunter_kb_list", "hunter_kb_search", "hunter_kb_read", "hunter_kb_recommend",
        "hunter_burp_bridge", "hunter_burp_repeater", "hunter_burp_proxy_search",
        "hunter_burp_scanner_issues", "hunter_burp_collaborator_workflow",
        "hunter_burp_import", "hunter_payload_list", "hunter_payload_search",
        "hunter_payload_get", "hunter_payload_generate", "hunter_session_list",
        "hunter_session_status", "hunter_agents_list", "hunter_phases_list", "hunter_report",
    }
    assert required - registered_functions(mcp_server) == set()
    assert len(required) == 45


def test_project_mcp_config_has_only_hunter_tools():
    config = json.loads(Path(r"D:\Open-tgtylab\.mcp.json").read_text(encoding="utf-8"))
    servers = config["mcpServers"]
    assert "hunter" not in servers
    assert servers["hunter_tools"]["args"][-1].replace("\\", "/").endswith("/hunter/mcp_server.py")


def test_codex_configs_have_only_hunter_tools():
    import tomllib
    paths = [
        Path(r"D:\Open-tgtylab\.codex\config.toml"),
        Path(r"C:\Users\Administrator\.codex\config.toml"),
    ]
    for path in paths:
        config = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        servers = config.get("mcp_servers", {})
        assert "hunter" not in servers
        assert "hunter_tools" in servers
        assert servers["hunter_tools"]["args"][-1].replace("\\", "/").endswith("/hunter/mcp_server.py")
