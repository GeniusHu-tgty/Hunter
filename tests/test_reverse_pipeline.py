import json
import asyncio
import zipfile
from pathlib import Path

import pytest

from core.reverse.binary_pipeline import (
    BinaryPipeline,
    detect_binary_type,
    detect_packers,
    identify_key_functions,
)
from core.reverse.android_pipeline import AndroidPipeline


def test_detects_binary_types_from_magic_and_apk_contents(tmp_path):
    pe = tmp_path / "sample.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 64)
    elf = tmp_path / "sample.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00" + b"\x00" * 64)
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='lab.test'/>")
        archive.writestr("classes.dex", b"dex\n035\x00")

    assert detect_binary_type(pe) == "pe"
    assert detect_binary_type(elf) == "elf"
    assert detect_binary_type(dex) == "dex"
    assert detect_binary_type(apk) == "apk"


def test_detects_known_packers_and_marks_unpack_requirement():
    result = detect_packers(
        b"MZ\x00UPX0\x00UPX1\x00Themida\x00VMProtect\x00",
        ["UPX!", "ASPack"],
    )

    assert set(result["detected"]) >= {"UPX", "ASPack", "Themida", "VMProtect"}
    assert result["requires_unpacking"] is True
    assert result["confidence"] > 0


def test_identifies_crypto_network_antidebug_c2_and_persistence_functions():
    imports = [
        {"name": "CryptEncrypt", "function": "FUN_401000"},
        {"name": "WinHttpSendRequest", "function": "FUN_402000"},
        {"name": "IsDebuggerPresent", "function": "FUN_403000"},
        {"name": "RegSetValueExW", "function": "FUN_404000"},
    ]
    strings = [
        {"value": "https://c2.example.test/gate", "function": "FUN_402000"},
        {"value": "AES/CBC/PKCS7Padding", "function": "FUN_401000"},
        {"value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "function": "FUN_404000"},
    ]
    call_graph = {
        "FUN_405000": ["FUN_401000", "FUN_402000"],
    }

    findings = identify_key_functions(imports, strings, call_graph)
    categories = {item["category"] for item in findings}

    assert {"crypto", "network", "anti_debug", "c2", "persistence"} <= categories
    c2 = next(item for item in findings if item["category"] == "c2")
    assert c2["function"] == "FUN_405000"
    assert c2["confidence"] >= 0.8


def test_binary_pipeline_orchestrates_six_steps_and_writes_artifacts(tmp_path):
    sample = tmp_path / "minimal.exe"
    sample.write_bytes(
        b"MZ\x00UPX0\x00"
        b"https://c2.example.test/api\x00"
        b"CryptEncrypt\x00WinHttpSendRequest\x00"
    )
    pipeline = BinaryPipeline(sample, output_root=tmp_path / "output")

    state = pipeline.run_all()

    assert [step["name"] for step in state["steps"]] == [
        "triage",
        "static",
        "identify",
        "plan",
        "capture",
        "produce",
    ]
    assert state["steps"][0]["status"] == "completed"
    assert state["steps"][4]["status"] == "awaiting-external"
    assert state["steps"][5]["status"] == "awaiting-external"
    assert state["results"]["produce"]["partial"] is True
    assert state["results"]["triage"]["requires_unpacking"] is True
    assert Path(state["artifacts"]["report_markdown"]).is_file()
    assert Path(state["artifacts"]["report_json"]).is_file()
    assert Path(state["artifacts"]["yara_rule"]).is_file()
    assert Path(state["artifacts"]["sigma_rule"]).is_file()
    assert Path(state["artifacts"]["iocs"]).is_file()
    persisted = json.loads(Path(state["state_path"]).read_text(encoding="utf-8"))
    assert persisted["pipeline_id"] == state["pipeline_id"]


def test_backend_results_are_normalized_into_static_function_map(tmp_path):
    sample = tmp_path / "backend.exe"
    sample.write_bytes(b"MZ\x00fallback-string\x00")
    calls = []

    def backend(server, tool, arguments):
        calls.append((server, tool, arguments))
        if tool == "triage_pe":
            return {
                "status": "ok",
                "hashes": {"sha256": "backend-sha256"},
                "imports": [{"name": "CryptEncrypt"}],
                "strings": [{"value": "https://backend.example.test"}],
            }
        if tool == "die_scan":
            return {"status": "ok", "detected": ["UPX"]}
        if tool == "ghidra_headless_analyze":
            return {
                "status": "ok",
                "summary_path": "summary.json",
                "summary": {
                    "program": {"entry_point": "00401000"},
                    "imports": [
                        {
                            "name": "CryptEncrypt",
                            "address": "00402000",
                            "xrefs": [{"function": "FUN_401100"}],
                        }
                    ],
                    "strings": [
                        {
                            "value": "https://backend.example.test",
                            "address": "00403000",
                            "xrefs": [{"function": "FUN_401200"}],
                        }
                    ],
                    "functions": [
                        {
                            "name": "FUN_401100",
                            "entry": "00401100",
                            "callees": ["FUN_401200"],
                            "import_refs": [{"name": "CryptEncrypt"}],
                            "string_refs": [],
                        }
                    ],
                    "exports": [{"name": "ExportedEntry", "address": "00401000"}],
                },
            }
        return {"status": "deferred"}

    pipeline = BinaryPipeline(
        sample,
        output_root=tmp_path / "backend-output",
        backend_runner=backend,
    )
    pipeline.run_step("triage")
    state = pipeline.run_step("static")
    static = state["results"]["static"]

    assert [call[1] for call in calls[:3]] == [
        "triage_pe",
        "die_scan",
        "ghidra_headless_analyze",
    ]
    assert static["entry_point"] == "00401000"
    assert static["exports"][0]["name"] == "ExportedEntry"
    assert static["functions"][0]["name"] == "FUN_401100"
    assert static["call_graph"]["FUN_401100"] == ["FUN_401200"]
    assert static["api_annotations"]["CryptEncrypt"] == "crypto operation"


def test_backend_error_marks_step_failed_instead_of_completed(tmp_path):
    sample = tmp_path / "failed-backend.exe"
    sample.write_bytes(b"MZ\x00")

    def backend(server, tool, arguments):
        return {"status": "error", "error": f"{tool} unavailable"}

    pipeline = BinaryPipeline(
        sample,
        output_root=tmp_path / "failed-output",
        backend_runner=backend,
    )

    with pytest.raises(RuntimeError, match="triage_pe unavailable"):
        pipeline.run_step("triage")

    assert pipeline.state["steps"][0]["status"] == "failed"
    assert pipeline.state["handoffs"][0]["status"] == "failed"


def test_backend_error_without_status_is_not_treated_as_success(tmp_path):
    sample = tmp_path / "implicit-error.exe"
    sample.write_bytes(b"MZ\x00")

    pipeline = BinaryPipeline(
        sample,
        output_root=tmp_path / "implicit-error-output",
        backend_runner=lambda server, tool, arguments: {"error": "backend timed out"},
    )

    with pytest.raises(RuntimeError, match="backend timed out"):
        pipeline.run_step("triage")


def test_pipeline_rejects_changed_sample_on_reload(tmp_path):
    sample = tmp_path / "mutable.exe"
    sample.write_bytes(b"MZ\x00first")
    pipeline = BinaryPipeline(sample, output_root=tmp_path / "mutable-output")
    pipeline.run_step("triage")
    sample.write_bytes(b"MZ\x00changed")

    with pytest.raises(ValueError, match="sample fingerprint changed"):
        BinaryPipeline.load(
            pipeline.pipeline_id,
            output_root=tmp_path / "mutable-output",
        )


def test_concurrent_pipeline_instances_detect_revision_conflict(tmp_path):
    sample = tmp_path / "concurrent.exe"
    sample.write_bytes(b"MZ\x00")
    output_root = tmp_path / "concurrent-output"
    first = BinaryPipeline(sample, output_root=output_root)
    first.run_step("triage")
    BinaryPipeline.load(first.pipeline_id, output_root=output_root)

    with pytest.raises(RuntimeError, match="concurrent pipeline modification"):
        first.run_step("static")


def test_pipeline_id_cannot_escape_output_root(tmp_path):
    sample = tmp_path / "safe.exe"
    sample.write_bytes(b"MZ\x00")

    with pytest.raises(ValueError, match="pipeline_id"):
        BinaryPipeline(
            sample,
            output_root=tmp_path / "safe-output",
            pipeline_id=r"..\escaped",
        )


def test_report_json_contains_final_produce_state(tmp_path):
    sample = tmp_path / "report.exe"
    sample.write_bytes(b"MZ\x00https://report.example.test\x00")
    state = BinaryPipeline(sample, output_root=tmp_path / "report-output").run_all()
    report = json.loads(Path(state["artifacts"]["report_json"]).read_text(encoding="utf-8"))
    produce = next(step for step in report["steps"] if step["name"] == "produce")

    assert produce["status"] == "awaiting-external"
    assert report["results"]["produce"]["partial"] is True
    assert report["artifacts"]["report_json"] == state["artifacts"]["report_json"]
    assert report["ioc_summary"]["dynamic_capture_present"] is False


def test_capture_step_runs_dependencies_before_dynamic_handoff(tmp_path):
    sample = tmp_path / "ordered.exe"
    sample.write_bytes(b"MZ\x00CryptEncrypt\x00")
    state = BinaryPipeline(
        sample,
        output_root=tmp_path / "ordered-output",
    ).run_step("capture")

    statuses = {step["name"]: step["status"] for step in state["steps"]}
    assert statuses["triage"] == "completed"
    assert statuses["static"] == "awaiting-external"
    assert statuses["identify"] == "completed"
    assert statuses["plan"] == "completed"
    assert statuses["capture"] == "awaiting-external"


def test_captured_crypto_material_generates_decrypt_script(tmp_path):
    sample = tmp_path / "crypto.exe"
    sample.write_bytes(b"MZ\x00CryptDecrypt\x00")

    def backend(server, tool, arguments):
        if tool == "ghidra_headless_analyze":
            return {"status": "ok", "summary": {}}
        if tool == "run_script":
            return {
                "status": "ok",
                "crypto": [
                    {
                        "algorithm": "xor",
                        "key_hex": "0f",
                        "iv_hex": "",
                    }
                ],
            }
        return {"status": "ok"}

    state = BinaryPipeline(
        sample,
        output_root=tmp_path / "crypto-output",
        backend_runner=backend,
    ).run_all()

    decrypt_script = Path(state["artifacts"]["decrypt_script"])
    script = decrypt_script.read_text(encoding="utf-8")
    assert decrypt_script.is_file()
    assert 'ALGORITHM = "xor"' in script
    assert 'KEY = bytes.fromhex("0f")' in script
    assert "def decrypt(data: bytes)" in script


def test_android_pipeline_extracts_manifest_surface_and_generates_hooks(tmp_path):
    apk = tmp_path / "sample.apk"
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="lab.authorized">
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:name=".App">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="false" />
  </application>
</manifest>"""
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex\n035\x00javax.crypto.Cipher okhttp3.OkHttpClient")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFJNI_OnLoad AES")

    state = AndroidPipeline(apk, output_root=tmp_path / "android-output").run_all()

    manifest_result = state["results"]["android_frontend"]
    assert manifest_result["package"] == "lab.authorized"
    assert manifest_result["permissions"] == ["android.permission.INTERNET"]
    assert manifest_result["exported_components"][0]["name"] == ".MainActivity"
    assert state["results"]["native"]["architectures"] == ["arm64-v8a"]
    hook_text = Path(state["artifacts"]["android_frida_hooks"]).read_text(encoding="utf-8")
    assert "okhttp3" in hook_text
    assert "javax.crypto.Cipher" in hook_text
    assert "android.webkit.WebView" in hook_text
    assert "android.util.Base64" in hook_text
    assert not any(
        item["tool"] == "triage_pe"
        for item in state["results"]["triage"]["handoffs"]
    )


def test_android_fresh_decrypt_plan_resolves_package_and_iocs(tmp_path):
    apk = tmp_path / "fresh.apk"
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="lab.fresh"><application><activity android:name=".Main" android:exported="true">
<intent-filter><data android:scheme="https" android:host="api.fresh.test" /></intent-filter>
</activity></application></manifest>"""
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(
            "classes.dex",
            b"dex\n035\x00https://api.fresh.test/v1 javax.crypto.Cipher okhttp3.OkHttpClient",
        )

    pipeline = AndroidPipeline(apk, output_root=tmp_path / "fresh-output")
    decrypt_plan = pipeline.decrypt_plan()
    iocs = pipeline.extract_iocs()

    assert "<package-name>" not in decrypt_plan["content"]
    assert "lab.fresh" in decrypt_plan["content"]
    assert "https://api.fresh.test/v1" in iocs["urls"]


def test_reverse_mcp_tools_create_and_reopen_pipeline(tmp_path, monkeypatch):
    import mcp_server

    sample = tmp_path / "mcp-sample.exe"
    sample.write_bytes(b"MZ\x00https://mcp.example.test\x00WinHttpSendRequest\x00")
    monkeypatch.setattr(mcp_server, "REVERSE_PIPELINE_ROOT", tmp_path / "mcp-output")

    created = json.loads(
        asyncio.run(mcp_server.hunter_reverse_binary(str(sample), "pe"))
    )
    pipeline_id = created["data"]["pipeline_id"]
    extracted = json.loads(
        asyncio.run(mcp_server.hunter_reverse_extract_iocs(pipeline_id))
    )
    rules = json.loads(
        asyncio.run(mcp_server.hunter_reverse_generate_rules(pipeline_id))
    )
    decrypt = json.loads(
        asyncio.run(mcp_server.hunter_reverse_decrypt_plan(pipeline_id))
    )

    assert created["status"] == "ok"
    assert extracted["status"] == "ok"
    assert "urls" in extracted["data"]["iocs"]
    assert Path(rules["data"]["yara_rule"]).is_file()
    assert Path(rules["data"]["sigma_rule"]).is_file()
    assert "handoffs" in decrypt["data"]
    for name in (
        "hunter_reverse_binary",
        "hunter_reverse_step",
        "hunter_reverse_extract_iocs",
        "hunter_reverse_generate_rules",
        "hunter_reverse_decrypt_plan",
    ):
        assert callable(getattr(mcp_server, name))
    registered = {
        tool.name for tool in asyncio.run(mcp_server.mcp.list_tools())
    }
    reverse_tools = {
        "hunter_reverse_binary",
        "hunter_reverse_step",
        "hunter_reverse_extract_iocs",
        "hunter_reverse_generate_rules",
        "hunter_reverse_decrypt_plan",
    }
    assert reverse_tools <= registered
    capabilities = json.loads(asyncio.run(mcp_server.hunter_capabilities()))
    health = json.loads(asyncio.run(mcp_server.hunter_healthcheck()))
    assert reverse_tools <= set(capabilities["tools"])
    assert reverse_tools <= set(health["mcp_tools"]["required"])
    assert not (reverse_tools & set(health["mcp_tools"]["missing"]))


def test_reverse_tools_are_required_by_integration_contract():
    contract_path = Path(__file__).parents[1] / "integration-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    required = set(contract["required_tools"])

    assert contract["minimum_tool_count"] >= 99
    assert {
        "hunter_reverse_binary",
        "hunter_reverse_step",
        "hunter_reverse_extract_iocs",
        "hunter_reverse_generate_rules",
        "hunter_reverse_decrypt_plan",
    } <= required
