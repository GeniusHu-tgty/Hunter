import json
from pathlib import Path

import pytest

from core.doctor import HunterDoctor, load_integration_contract


def make_contract(path: Path):
    data = {
        "contract_version": "1.0",
        "server_name": "hunter_tools",
        "minimum_tool_count": 2,
        "required_tools": ["hunter_healthcheck", "hunter_doctor"],
        "workspace_schema_version": "1.0",
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return data


def test_contract_load_and_check(tmp_path):
    contract_path = tmp_path / "integration-contract.json"
    make_contract(contract_path)
    doctor = HunterDoctor(tmp_path, registered_tools=["hunter_healthcheck", "hunter_doctor"], contract_path=contract_path)
    result = doctor.contract_check()
    assert result["status"] == "ok"
    assert result["data"]["server_name"] == "hunter_tools"
    assert result["data"]["missing_tools"] == []


def test_contract_check_detects_missing_tools_and_count(tmp_path):
    contract_path = tmp_path / "integration-contract.json"
    make_contract(contract_path)
    result = HunterDoctor(tmp_path, registered_tools=["hunter_healthcheck"], contract_path=contract_path).contract_check()
    assert result["status"] == "error"
    assert "hunter_doctor" in result["data"]["missing_tools"]
    assert result["data"]["minimum_tool_count_satisfied"] is False


def test_config_audit_detects_legacy_registration_portably(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('[mcp_servers.hunter]\ncommand="python"\n[mcp_servers.hunter_tools]\ncommand="python"\n', encoding="utf-8")
    doctor = HunterDoctor(tmp_path, registered_tools=[], config_paths=[config])
    result = doctor.config_audit()
    assert result["status"] == "error"
    assert result["data"]["legacy_registrations"] == [str(config.resolve())]


def test_runtime_status_does_not_require_windows_or_fixed_drive(tmp_path):
    doctor = HunterDoctor(tmp_path, registered_tools=["hunter_doctor"])
    result = doctor.runtime_status()
    assert result["status"] == "ok"
    assert result["data"]["python_executable"]
    assert result["data"]["platform"]
    assert "D:\\" not in json.dumps(result)


def test_doctor_aggregates_checks(tmp_path):
    contract_path = tmp_path / "integration-contract.json"
    data = make_contract(contract_path)
    data["minimum_tool_count"] = 2
    contract_path.write_text(json.dumps(data), encoding="utf-8")
    doctor = HunterDoctor(tmp_path, registered_tools=["hunter_healthcheck", "hunter_doctor"], contract_path=contract_path, config_paths=[])
    result = doctor.run()
    assert result["tool"] == "hunter_doctor"
    assert set(result["data"]["checks"]) == {"contract", "config", "runtime"}

