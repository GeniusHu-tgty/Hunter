import asyncio
import json

import pytest

import mcp_server
from core.doctor import HunterDoctor, load_integration_contract


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
    expected_counts = inventory["counts"]
    core_count = expected_counts["core"]
    extension_count = expected_counts["extensions"]
    unknown_count = expected_counts["unknown"]

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
    assert health["mcp_tools"]["counts"] == expected_counts

    capabilities = load_json(run_async(mcp_server.hunter_capabilities()))
    assert capabilities["framework"] == "Hunter"
    assert "recommended_workflow" in capabilities
    assert "tools" in capabilities
    assert capabilities["tools"]["hunter_healthcheck"]["category"] == "meta"
    assert capabilities["tools"]["hunter_auto_sqli"]["category"] == "auto-vuln"
    assert capabilities["tool_counts"]["core"] == core_count
    assert capabilities["tool_counts"]["extensions"] == extension_count
    assert capabilities["tool_counts"]["unknown"] == unknown_count
    assert capabilities["tool_counts"] == expected_counts

    runtime = load_json(run_async(mcp_server.hunter_runtime_status()))
    assert runtime["data"]["core_tool_count"] == core_count
    assert runtime["data"]["extension_tool_count"] == extension_count
    assert runtime["data"]["unknown_tool_count"] == unknown_count
    assert runtime["data"]["tool_counts"] == expected_counts

    doctor = load_json(run_async(mcp_server.hunter_doctor()))
    assert doctor["data"]["tool_counts"]["core"] == core_count
    assert doctor["data"]["tool_counts"]["extensions"] == extension_count
    assert doctor["data"]["tool_counts"]["unknown"] == unknown_count
    assert doctor["data"]["tool_counts"] == expected_counts

    contract = load_json(run_async(mcp_server.hunter_contract_check()))
    assert contract["data"]["tool_counts"] == expected_counts
    assert contract["data"]["registered_core_tool_count"] == core_count
    assert contract["data"]["extension_tool_count"] == extension_count
    assert contract["data"]["unknown_tool_count"] == unknown_count
    assert contract["data"]["registered_tool_count"] == (
        expected_counts["total"]
    )


def test_invalid_extension_provenance_reaches_inventory_and_diagnostics(
    monkeypatch,
    tmp_path,
):
    contract_path = write_contract(
        tmp_path,
        exact_core_tool_count=2,
        optional_extension_namespaces=["re_"],
        unknown_tool_policy="error",
    )
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {
            "hunter_doctor": object(),
            "hunter_healthcheck": object(),
            "bad_tool": object(),
        },
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_SOURCES",
        {"fixture_extension": {"bad_tool"}},
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_COLLISIONS",
        [],
    )
    monkeypatch.setattr(
        mcp_server,
        "INTEGRATION_CONTRACT_PATH",
        contract_path,
    )

    inventory = mcp_server._registered_tool_inventory()
    health = load_json(run_async(mcp_server.hunter_healthcheck()))
    capabilities = load_json(
        run_async(mcp_server.hunter_capabilities())
    )
    runtime = load_json(
        run_async(mcp_server.hunter_runtime_status())
    )
    contract = load_json(
        run_async(mcp_server.hunter_contract_check())
    )

    assert inventory["invalid_extension_tools"] == ["bad_tool"]
    assert health["mcp_tools"]["invalid_extension_tools"] == [
        "bad_tool"
    ]
    assert capabilities["invalid_extension_tools"] == ["bad_tool"]
    assert runtime["data"]["invalid_extension_tools"] == ["bad_tool"]
    assert contract["status"] == "error"
    assert contract["data"]["invalid_extension_tools"] == [
        "bad_tool"
    ]

    direct_doctor = HunterDoctor(
        tmp_path,
        registered_tools=[
            "hunter_healthcheck",
            "hunter_doctor",
        ],
        extension_tools={
            "fixture_extension": ["bad_tool"],
        },
        invalid_extension_tools=[
            "legacy_bad",
            "bad_tool",
            "legacy_bad",
        ],
        contract_path=contract_path,
        config_paths=[],
    )
    assert direct_doctor.contract_check()["data"][
        "invalid_extension_tools"
    ] == ["bad_tool", "legacy_bad"]
    assert direct_doctor.runtime_status()["data"][
        "invalid_extension_tools"
    ] == ["bad_tool", "legacy_bad"]

    invalid_only = HunterDoctor(
        tmp_path,
        registered_tools=[
            "hunter_healthcheck",
            "hunter_doctor",
        ],
        invalid_extension_tools=["legacy_bad"],
        contract_path=contract_path,
        config_paths=[],
    )
    invalid_only_contract = invalid_only.contract_check()
    assert invalid_only_contract["status"] == "error"
    assert invalid_only_contract["data"]["unknown_tools"] == [
        "legacy_bad"
    ]
    assert invalid_only_contract["data"]["tool_counts"] == {
        "core": 2,
        "extensions": 0,
        "unknown": 1,
        "total": 3,
    }


_MISSING = object()


def write_contract(
    tmp_path,
    *,
    exact_core_tool_count=_MISSING,
    optional_extension_namespaces=None,
    unknown_tool_policy="error",
):
    contract_path = tmp_path / "integration-contract.json"
    data = {
        "contract_version": "1.0",
        "server_name": "hunter_tools",
        "minimum_tool_count": 2,
        "optional_extension_namespaces": (
            optional_extension_namespaces
            if optional_extension_namespaces is not None
            else ["re_"]
        ),
        "unknown_tool_policy": unknown_tool_policy,
        "required_tools": [
            "hunter_healthcheck",
            "hunter_doctor",
        ],
        "workspace_schema_version": "1.0",
    }
    if exact_core_tool_count is not _MISSING:
        data["exact_core_tool_count"] = exact_core_tool_count
    contract_path.write_text(json.dumps(data), encoding="utf-8")
    return contract_path


def write_exact_contract(tmp_path):
    return write_contract(tmp_path, exact_core_tool_count=2)


def test_legacy_contract_without_exact_count_remains_minimum_only(
    tmp_path,
):
    contract_path = write_contract(tmp_path)
    contract = load_integration_contract(contract_path)
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

    assert "exact_core_tool_count" not in contract
    assert result["status"] == "ok"
    assert result["data"]["unexpected_core_tools"] == [
        "hunter_extra"
    ]
    assert result["data"]["exact_core_tool_count_satisfied"] is None


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


def test_doctor_inventory_is_globally_unique_and_mutually_exclusive(
    tmp_path,
):
    contract_path = write_contract(
        tmp_path,
        exact_core_tool_count=2,
        unknown_tool_policy="warning",
    )
    doctor = HunterDoctor(
        tmp_path,
        registered_tools=[
            "hunter_healthcheck",
            "hunter_doctor",
            "hunter_doctor",
        ],
        extension_tools={
            "z_source": [
                "re_shared",
                "re_unique",
                "invalid_extension",
            ],
            "a_source": [
                "re_shared",
                "hunter_doctor",
            ],
        },
        unknown_tools=[
            "hunter_healthcheck",
            "re_unique",
            "invalid_extension",
            "unclassified_tool",
        ],
        contract_path=contract_path,
        config_paths=[],
    )

    contract = doctor.contract_check()
    runtime = doctor.runtime_status()
    inventory = contract["data"]
    core = set(doctor.registered_tools)
    extensions = {
        name
        for names in inventory["extension_tools"].values()
        for name in names
    }
    unknown = set(inventory["unknown_tools"])

    assert contract["status"] == "error"
    assert inventory["invalid_extension_tools"] == [
        "invalid_extension"
    ]
    assert core.isdisjoint(extensions)
    assert core.isdisjoint(unknown)
    assert extensions.isdisjoint(unknown)
    assert extensions == {"re_shared", "re_unique"}
    assert inventory["extension_tools"] == {
        "contract_extensions": ["re_shared"],
        "z_source": ["re_unique"],
    }
    assert unknown == {
        "invalid_extension",
        "unclassified_tool",
    }
    assert inventory["collisions"] == [
        {
            "tool": "re_shared",
            "sources": ["a_source", "z_source"],
        }
    ]
    assert inventory["collision_count"] == 1
    assert inventory["errors"] == [
        (
            "Extension tool source collisions: "
            "re_shared (a_source, z_source)"
        )
    ]
    assert inventory["extension_tool_count"] == 2
    assert inventory["unknown_tool_count"] == 2
    assert inventory["registered_tool_count"] == 6
    assert runtime["data"]["core_tool_count"] == 2
    assert runtime["data"]["extension_tool_count"] == 2
    assert runtime["data"]["unknown_tool_count"] == 2
    assert runtime["data"]["registered_tool_count"] == 6
    assert runtime["data"]["collisions"] == inventory["collisions"]
    assert runtime["data"]["collision_count"] == 1


def test_mcp_loader_collision_makes_contract_check_error(
    monkeypatch,
    tmp_path,
):
    contract_path = write_contract(
        tmp_path,
        exact_core_tool_count=2,
        unknown_tool_policy="warning",
    )
    collision = {
        "tool": "re_collision",
        "sources": [
            "contract_extensions",
            "reverse_lab_tools",
        ],
    }
    inventory = {
        "core": ["hunter_doctor", "hunter_healthcheck"],
        "extensions": {
            "contract_extensions": ["re_collision"],
        },
        "unknown": [],
        "collisions": [collision],
        "collision_count": 1,
        "counts": {
            "core": 2,
            "extensions": 1,
            "unknown": 0,
            "total": 3,
        },
    }
    monkeypatch.setattr(
        mcp_server,
        "_registered_tool_inventory",
        lambda: inventory,
    )
    monkeypatch.setattr(
        mcp_server,
        "INTEGRATION_CONTRACT_PATH",
        contract_path,
    )

    result = load_json(
        run_async(mcp_server.hunter_contract_check())
    )

    assert result["status"] == "error"
    assert result["data"]["collisions"] == [collision]
    assert result["data"]["collision_count"] == 1
    assert result["data"]["errors"] == [
        (
            "Extension tool source collisions: "
            "re_collision "
            "(contract_extensions, reverse_lab_tools)"
        )
    ]


def test_doctor_uses_non_re_extension_namespace_from_contract(
    tmp_path,
):
    contract_path = write_contract(
        tmp_path,
        exact_core_tool_count=2,
        optional_extension_namespaces=["plugin_"],
    )
    result = HunterDoctor(
        tmp_path,
        registered_tools=["hunter_healthcheck", "hunter_doctor"],
        extension_tools={
            "plugin_tools": ["plugin_triage"],
        },
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()

    assert result["status"] == "ok"
    assert result["data"]["extension_tools"] == {
        "plugin_tools": ["plugin_triage"],
    }
    assert result["data"]["extension_tool_count"] == 1
    assert result["data"]["unknown_tools"] == []


@pytest.mark.parametrize(
    ("policy", "expected_status", "expects_warning"),
    [
        ("error", "error", False),
        ("warning", "ok", True),
    ],
)
def test_doctor_unknown_policy_error_and_warning(
    tmp_path,
    policy,
    expected_status,
    expects_warning,
):
    contract_path = write_contract(
        tmp_path,
        exact_core_tool_count=2,
        unknown_tool_policy=policy,
    )
    result = HunterDoctor(
        tmp_path,
        registered_tools=["hunter_healthcheck", "hunter_doctor"],
        unknown_tools=["plugin_unclassified"],
        contract_path=contract_path,
        config_paths=[],
    ).contract_check()

    assert result["status"] == expected_status
    assert result["data"]["unknown_tool_policy"] == policy
    assert bool(result["data"]["warnings"]) is expects_warning


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
