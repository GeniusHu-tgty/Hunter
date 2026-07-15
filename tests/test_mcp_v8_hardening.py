import asyncio
import json

import pytest

import mcp_server
from core.doctor import HunterDoctor


def run_async(coro):
    return asyncio.run(coro)


def load_json(text):
    return json.loads(text)


def test_v8_mcp_tool_functions_exist():
    expected = [
        "hunter_auto_sqli",
        "hunter_auto_xss",
        "hunter_auto_ssrf",
        "hunter_auto_xxe",
        "hunter_auto_ssti",
        "hunter_auto_cmd",
        "hunter_auto_idor",
        "hunter_healthcheck",
        "hunter_capabilities",
        "hunter_recommend_next",
    ]
    missing = [name for name in expected if not hasattr(mcp_server, name)]
    assert missing == []


def test_ssti_cmd_idor_wrappers_call_real_impls(monkeypatch):
    import core.auto_ssti as auto_ssti
    import core.auto_cmd as auto_cmd
    import core.auto_idor as auto_idor

    calls = []

    def fake_ssti(base_url, param="q", method="GET"):
        calls.append(("ssti", base_url, param, method))
        return {"scanner": "ssti", "target": base_url, "param": param, "method": method}

    def fake_cmd(base_url, param="cmd", method="GET"):
        calls.append(("cmd", base_url, param, method))
        return {"scanner": "cmd", "target": base_url, "param": param, "method": method}

    def fake_idor(url="", url_template="", id_range="1-5", current_id="1", method="GET", cookie=""):
        calls.append(("idor", url, url_template, id_range, current_id, method, cookie))
        return {"scanner": "idor", "target": url, "cookie": cookie}

    monkeypatch.setattr(auto_ssti, "auto_ssti_impl", fake_ssti)
    monkeypatch.setattr(auto_cmd, "auto_cmd_impl", fake_cmd)
    monkeypatch.setattr(auto_idor, "auto_idor_impl", fake_idor)

    assert load_json(run_async(mcp_server.hunter_auto_ssti("https://t/?q=1", "q", "GET")))["scanner"] == "ssti"
    assert load_json(run_async(mcp_server.hunter_auto_cmd("https://t/?cmd=id", "cmd", "POST")))["scanner"] == "cmd"
    assert load_json(run_async(mcp_server.hunter_auto_idor("https://t", "/api/user/1", "sid=REDACTED")))["scanner"] == "idor"
    assert calls[0] == ("ssti", "https://t/?q=1", "q", "GET")
    assert calls[1] == ("cmd", "https://t/?cmd=id", "cmd", "POST")
    assert calls[2][0] == "idor"
    assert calls[2][1] == "https://t/api/user/1"
    assert calls[2][-1] == "sid=REDACTED"


def test_new_auto_wrappers_call_real_impls(monkeypatch):
    import core.auto_sqli as auto_sqli
    import core.auto_xss as auto_xss
    import core.auto_ssrf as auto_ssrf
    import core.auto_xxe as auto_xxe

    monkeypatch.setattr(auto_sqli, "auto_sqli_impl", lambda base_url, param="category", method="GET", **kwargs: {"scanner": "sqli", "target": base_url, "param": param, "method": method})
    monkeypatch.setattr(auto_xss, "auto_xss_impl", lambda base_url, param="q", method="GET", **kwargs: {"scanner": "xss", "target": base_url, "param": param, "method": method})
    monkeypatch.setattr(auto_ssrf, "auto_ssrf_impl", lambda base_url, param="url", method="GET", collaborator="", **kwargs: {"scanner": "ssrf", "target": base_url, "param": param, "collaborator": collaborator})
    monkeypatch.setattr(auto_xxe, "auto_xxe_impl", lambda base_url, param="", method="POST", **kwargs: {"scanner": "xxe", "target": base_url, "method": method})

    assert load_json(run_async(mcp_server.hunter_auto_sqli("https://t/?id=1", "id", "GET")))["scanner"] == "sqli"
    assert load_json(run_async(mcp_server.hunter_auto_xss("https://t/?q=1", "q", "GET")))["scanner"] == "xss"
    assert load_json(run_async(mcp_server.hunter_auto_ssrf("https://t/fetch?url=x", "url", "GET", "cb.test")))["scanner"] == "ssrf"
    assert load_json(run_async(mcp_server.hunter_auto_xxe("https://t/xml", "xml", "POST")))["scanner"] == "xxe"


def test_healthcheck_and_capabilities_are_local_and_structured():
    inventory = mcp_server._registered_tool_inventory()
    core_count = len(inventory["core"])
    extension_count = sum(
        len(names) for names in inventory["extensions"].values()
    )
    unknown_count = len(inventory["unknown"])

    health = load_json(run_async(mcp_server.hunter_healthcheck()))
    assert health["framework"] == "Hunter"
    assert "status" in health
    assert "external_tools" in health
    assert "payloads" in health
    assert "mcp_tools" in health
    assert "hunter_auto_sqli" in health["mcp_tools"]["registered"]
    assert health["mcp_tools"]["core_count"] == core_count
    assert health["mcp_tools"]["extension_count"] == extension_count
    assert health["mcp_tools"]["unknown_count"] == unknown_count
    assert health["mcp_tools"]["total_registered"] == (
        core_count + extension_count + unknown_count
    )

    capabilities = load_json(run_async(mcp_server.hunter_capabilities()))
    assert capabilities["framework"] == "Hunter"
    assert "recommended_workflow" in capabilities
    assert "tools" in capabilities
    assert capabilities["tools"]["hunter_healthcheck"]["category"] == "meta"
    assert capabilities["tools"]["hunter_auto_sqli"]["category"] == "auto-vuln"
    assert capabilities["tool_counts"]["core"] == core_count
    assert capabilities["tool_counts"]["extensions"] == extension_count
    assert capabilities["tool_counts"]["unknown"] == unknown_count

    runtime = load_json(run_async(mcp_server.hunter_runtime_status()))
    assert runtime["data"]["core_tool_count"] == core_count
    assert runtime["data"]["extension_tool_count"] == extension_count
    assert runtime["data"]["unknown_tool_count"] == unknown_count

    doctor = load_json(run_async(mcp_server.hunter_doctor()))
    assert doctor["data"]["tool_counts"]["core"] == core_count
    assert doctor["data"]["tool_counts"]["extensions"] == extension_count
    assert doctor["data"]["tool_counts"]["unknown"] == unknown_count


def write_exact_contract(tmp_path):
    contract_path = tmp_path / "integration-contract.json"
    contract_path.write_text(
        json.dumps(
            {
                "contract_version": "1.0",
                "server_name": "hunter_tools",
                "minimum_tool_count": 2,
                "exact_core_tool_count": 2,
                "optional_extension_namespaces": ["re_"],
                "unknown_tool_policy": "error",
                "required_tools": [
                    "hunter_healthcheck",
                    "hunter_doctor",
                ],
                "workspace_schema_version": "1.0",
            }
        ),
        encoding="utf-8",
    )
    return contract_path


def test_doctor_extensions_are_optional_and_cannot_fill_missing_core(
    tmp_path,
):
    contract_path = write_exact_contract(tmp_path)
    without_extensions = HunterDoctor(
        tmp_path,
        registered_tools=["hunter_healthcheck", "hunter_doctor"],
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()
    with_extensions = HunterDoctor(
        tmp_path,
        registered_tools=["hunter_healthcheck", "hunter_doctor"],
        extension_tools={
            "reverse_lab_tools": ["re_triage_pe"],
        },
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()
    missing_core = HunterDoctor(
        tmp_path,
        registered_tools=["hunter_healthcheck"],
        extension_tools={
            "reverse_lab_tools": [
                "re_hunter_doctor",
                "re_triage_pe",
            ],
        },
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()

    assert without_extensions["status"] == "ok"
    assert with_extensions["status"] == "ok"
    assert with_extensions["data"]["extension_tool_count"] == 1
    assert missing_core["status"] == "error"
    assert missing_core["data"]["missing_core_tools"] == [
        "hunter_doctor"
    ]


def test_doctor_rejects_unexpected_core_tools(tmp_path):
    contract_path = write_exact_contract(tmp_path)
    result = HunterDoctor(
        tmp_path,
        registered_tools=[
            "hunter_healthcheck",
            "hunter_doctor",
            "hunter_extra",
        ],
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()

    assert result["status"] == "error"
    assert result["data"]["unexpected_core_tools"] == [
        "hunter_extra"
    ]


def test_doctor_reports_unknown_tools_using_contract_policy(tmp_path):
    contract_path = write_exact_contract(tmp_path)
    result = HunterDoctor(
        tmp_path,
        registered_tools=["hunter_healthcheck", "hunter_doctor"],
        unknown_tools=["plugin_unclassified"],
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()

    assert result["status"] == "error"
    assert result["data"]["unknown_tool_policy"] == "error"
    assert result["data"]["unknown_tools"] == [
        "plugin_unclassified"
    ]


def test_recommend_next_prioritizes_logic_and_proof_goals():
    result = load_json(run_async(mcp_server.hunter_recommend_next(
        target="https://example.test",
        signals=["jwt", "idor", "cors", "swagger"],
        finding="API exposes userId and X-Id-Token; CORS allows Authorization header",
    )))
    tools = [item["tool"] for item in result["recommendations"]]
    assert tools[0] in {"hunter_auto_idor", "hunter_auto_access_control"}
    assert "hunter_auto_jwt" in tools
    assert "hunter_auto_cors" in tools
    assert result["proof_goals"]
    assert all("reason" in item for item in result["recommendations"])



def test_recommend_next_routes_chinese_access_control_signals():
    result = load_json(
        run_async(
            mcp_server.hunter_recommend_next(
                target="https://example.test/api/user/1",
                signals=["\u8d8a\u6743", "\u6c34\u5e73\u8d8a\u6743"],
                finding="",
            )
        )
    )
    tools = [item["tool"] for item in result["recommendations"]]
    assert "hunter_auto_idor" in tools
    assert "hunter_auto_access_control" in tools
