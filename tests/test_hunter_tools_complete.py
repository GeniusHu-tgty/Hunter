
import json
from pathlib import Path
import subprocess

import mcp_server


def registered_functions(module):
    return {
        name for name, value in vars(module).items()
        if name.startswith("hunter_") and callable(value)
    }


def test_complete_server_is_named_hunter_tools():
    assert mcp_server.mcp.name == "hunter_tools"


def test_fastmcp_registry_matches_hunter_tool_functions():
    inventory_factory = getattr(
        mcp_server,
        "_registered_tool_inventory",
        None,
    )
    assert callable(inventory_factory)
    inventory = inventory_factory()
    registry = set(mcp_server.mcp._tool_manager._tools)
    functions = registered_functions(mcp_server)
    extension_names = set(
        inventory["extensions"]["reverse_lab_tools"]
    )
    assert inventory["unknown"] == []
    assert registry == functions | extension_names
    assert len(functions) == 113


def test_registered_tool_inventory_separates_core_and_extensions():
    inventory_factory = getattr(
        mcp_server,
        "_registered_tool_inventory",
        None,
    )
    assert callable(inventory_factory)
    inventory = inventory_factory()
    functions = registered_functions(mcp_server)
    core = set(inventory["core"])
    extensions = set(
        inventory["extensions"]["reverse_lab_tools"]
    )

    assert core == functions
    assert all(name.startswith("re_") for name in extensions)
    assert core.isdisjoint(extensions)
    assert inventory["unknown"] == []
    assert len(core) == 113
    assert set(mcp_server._registered_hunter_tools()) == core


def test_internal_tool_inventory_uses_fastmcp_registry(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "hunter_unregistered_probe",
        lambda: None,
        raising=False,
    )

    assert (
        "hunter_unregistered_probe"
        not in mcp_server._registered_hunter_tools()
    )


def test_integration_contract_exactly_matches_core_tools():
    contract = json.loads(
        (Path(__file__).parents[1] / "integration-contract.json").read_text(
            encoding="utf-8"
        )
    )
    functions = registered_functions(mcp_server)

    assert set(contract["required_tools"]) == functions
    assert len(contract["required_tools"]) == 113
    assert contract["minimum_tool_count"] == 113
    assert contract["exact_core_tool_count"] == 113
    assert contract["optional_extension_namespaces"] == ["re_"]
    assert "hunter_auto_attack" in contract["required_tools"]
    assert "hunter_fast_recon" in contract["required_tools"]


def test_complete_server_exposes_all_legacy_and_v81_tools():
    required = {
        "hunter_scan", "hunter_recon", "hunter_vuln_scan",
        "hunter_subdomain", "hunter_port_scan", "hunter_tech_detect",
        "hunter_dir_enum", "hunter_js_analyze", "hunter_js_unpack",
        "hunter_js_deobfuscate", "hunter_js_extract_api",
        "hunter_js_extract_signature", "hunter_js_full_analysis",
        "hunter_auto_attack", "hunter_auto_sqli", "hunter_auto_xss", "hunter_auto_ssrf",
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
        "hunter_stealth_request", "hunter_stealth_scan", "hunter_session_create",
        "hunter_session_state", "hunter_set_proxy_pool",
        "hunter_reverse_binary", "hunter_reverse_step",
        "hunter_reverse_extract_iocs", "hunter_reverse_generate_rules",
        "hunter_reverse_decrypt_plan",
    }
    assert required - registered_functions(mcp_server) == set()
    assert len(required) == 61


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


def test_skill_document_has_no_corrupt_placeholder_runs():
    skill = (Path(__file__).parents[1] / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "????" not in skill


def test_file_upload_bypass_reference_exists():
    payload = (
        Path(__file__).parents[1]
        / "payloads"
        / "file-upload"
        / "file-upload-bypass.md"
    )
    assert payload.is_file()


def test_git_does_not_track_python_bytecode():
    root = Path(__file__).parents[1]
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    tracked = [
        line
        for line in proc.stdout.splitlines()
        if "__pycache__/" in line or line.endswith(".pyc")
    ]
    assert tracked == []
