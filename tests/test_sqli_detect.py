from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Response:
    status_code: int
    text: str
    headers: dict
    elapsed_seconds: float = 0.01

    @property
    def elapsed(self):
        class Elapsed:
            def __init__(self, seconds):
                self.seconds = seconds

            def total_seconds(self):
                return self.seconds

        return Elapsed(self.elapsed_seconds)


class ScriptedSession:
    def __init__(self, responder, cookies=None):
        self.responder = responder
        self.calls = []
        self.headers = {}
        self.cookies = cookies or {}

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responder(method, url, kwargs)


class RecordingMemory:
    def __init__(self):
        self.attempts = []

    def record_attempt(self, **kwargs):
        self.attempts.append(kwargs)
        return kwargs


def test_error_detection_identifies_mysql_and_records_every_probe():
    from core.sqli_detect import SqliDetector

    def responder(method, url, kwargs):
        value = (kwargs.get("params") or kwargs.get("data"))["id"]
        body = "You have an error in your SQL syntax; check MySQL manual 1064" if "'" in value else "normal"
        return Response(500 if body != "normal" else 200, body, {})

    memory = RecordingMemory()
    detector = SqliDetector(
        "https://target.test/item?id=7",
        param="id",
        session=ScriptedSession(responder),
        technique_memory=memory,
        waf_type="cloudflare",
    )

    result = detector.detect()

    assert result["vulnerable"] is True
    assert result["detection_type"] == "error-based"
    assert result["db_type"] == "mysql"
    assert result["evidence"]["reproduction_count"] == 3
    assert len(memory.attempts) == 5
    assert {item["metadata"]["payload"] for item in memory.attempts} >= {"7\'", '7"', "7\\"}
    assert all(item["target_url"] == "https://target.test/item?id=7" for item in memory.attempts)
    assert all(item["waf_type"] == "cloudflare" for item in memory.attempts)
    assert any(item["success"] for item in memory.attempts)


def test_boolean_detection_uses_significant_length_difference():
    from core.sqli_detect import SqliDetector

    def responder(method, url, kwargs):
        value = (kwargs.get("params") or kwargs.get("data"))["id"]
        if "AND 1=2" in value:
            return Response(200, "not found", {})
        return Response(200, "product:" + ("x" * 300), {})

    detector = SqliDetector(
        "https://target.test/item?id=7",
        param="id",
        session=ScriptedSession(responder),
        technique_memory=RecordingMemory(),
    )

    result = detector.detect()

    assert result["vulnerable"] is True
    assert result["detection_type"] == "boolean-based"
    assert result["boolean_analysis"]["significant"] is True
    assert result["evidence"]["metadata"]["boolean_blind"] is True


def test_query_parameters_are_preserved_and_only_target_parameter_changes():
    from core.sqli_detect import SqliDetector

    session = ScriptedSession(lambda method, url, kwargs: Response(200, "same", {}))
    detector = SqliDetector(
        "https://target.test/item?lang=en&id=7",
        param="id",
        session=session,
        technique_memory=RecordingMemory(),
    )

    detector.detect()

    first_params = session.calls[0][2]["params"]
    assert first_params["lang"] == "en"
    assert first_params["id"].startswith("7")


def test_auto_sqli_defaults_to_lightweight_detector(monkeypatch):
    import core.auto_sqli as auto_sqli

    calls = []

    class FakeDetector:
        def __init__(self, target, **kwargs):
            calls.append((target, kwargs))

        def detect(self):
            return {"scanner": "sqli", "engine": "lightweight", "vulnerable": False}

    monkeypatch.setattr(auto_sqli, "SqliDetector", FakeDetector)
    result = auto_sqli.auto_sqli_impl("https://target.test/?id=1", param="id")

    assert result["engine"] == "lightweight"
    assert calls[0][1]["param"] == "id"


def test_sqlmap_runs_only_after_confirmation_and_explicit_deep_action(monkeypatch):
    import core.auto_sqli as auto_sqli

    monkeypatch.setattr(
        auto_sqli.SqliDetector,
        "detect",
        lambda self: {
            "scanner": "sqli",
            "engine": "lightweight",
            "vulnerable": True,
            "injection_point": "id",
        },
    )
    calls = []
    monkeypatch.setattr(auto_sqli, "_run_sqlmap", lambda **kwargs: calls.append(kwargs) or {"status": "completed"})

    shallow = auto_sqli.auto_sqli_impl("https://target.test/?id=1", param="id")
    deep = auto_sqli.auto_sqli_impl(
        "https://target.test/?id=1",
        param="id",
        deep_action="tables",
        session=ScriptedSession(lambda *args: Response(200, "", {}), cookies={"sid": "secret"}),
    )

    assert "deep_exploitation" not in shallow
    assert deep["deep_exploitation"]["status"] == "completed"
    assert calls[0]["deep_action"] == "tables"
    assert calls[0]["cookie_header"] == "sid=secret"


def test_mcp_session_is_passed_to_real_lightweight_detector(monkeypatch):
    import asyncio
    import json
    import mcp_server

    class ResponseSession:
        session_id = "stealth-known"
        headers = {}
        cookies = {}

        def request(self, method, url, **kwargs):
            value = (kwargs.get("params") or kwargs.get("data"))["id"]
            body = "ORA-00933 SQL command not properly ended" if "\'" in value else "normal"
            return Response(500 if body != "normal" else 200, body, {})

    detection_session = ResponseSession()

    class FakeStealthClient:
        def detection_session(self, session_id):
            assert session_id == "stealth-known"
            return detection_session

    monkeypatch.setattr(mcp_server, "_get_stealth_client", lambda: FakeStealthClient())
    result = json.loads(asyncio.run(mcp_server.hunter_auto_sqli(
        "https://target.test/item?id=1",
        param="id",
        session_id="stealth-known",
    )))

    assert result["engine"] == "lightweight"
    assert result["session_id"] == "stealth-known"
    assert result["db_type"] == "oracle"
    assert result["verdict"]["verdict"] == "verified"


def test_sqlmap_uses_temporary_request_file_and_removes_it(monkeypatch, tmp_path):
    import core.auto_sqli as auto_sqli

    request_paths = []

    class Completed:
        returncode = 0
        stdout = "done"
        stderr = ""

    def fake_run(command, **kwargs):
        request_path = command[command.index("-r") + 1]
        request_paths.append(request_path)
        content = Path(request_path).read_text(encoding="utf-8")
        assert "Cookie: sid=secret" in content
        assert "sid=secret" not in command
        assert kwargs["shell"] is False
        return Completed()

    monkeypatch.setattr(auto_sqli.shutil, "which", lambda name: "sqlmap")
    monkeypatch.setattr(auto_sqli.subprocess, "run", fake_run)

    result = auto_sqli._run_sqlmap(
        target="https://target.test/item?id=1",
        param="id",
        method="GET",
        deep_action="tables",
        cookie_header="sid=secret",
        headers={"User-Agent": "browser"},
    )

    assert result["status"] == "completed"
    assert request_paths and not Path(request_paths[0]).exists()


def test_confirmed_injection_registers_workflow_evidence(tmp_path):
    from core.sqli_detect import SqliDetector
    from core.workflow import WorkflowKernel

    kernel = WorkflowKernel(tmp_path)
    kernel.create(
        "sqli-case",
        "Confirm SQL injection",
        inputs=[{"type": "url", "value": "https://target.test/item?id=1"}],
    )

    def responder(method, url, kwargs):
        value = (kwargs.get("params") or kwargs.get("data"))["id"]
        body = "SQLite error near sqlite_master" if "\'" in value else "normal"
        return Response(500 if body != "normal" else 200, body, {})

    result = SqliDetector(
        "https://target.test/item?id=1",
        param="id",
        session=ScriptedSession(responder),
        technique_memory=RecordingMemory(),
        case_slug="sqli-case",
        workspace_root=tmp_path,
    ).detect()
    state = kernel.materialize("sqli-case")

    assert result["evidence_registration"]["workflow_registered"] is True
    assert state["evidence"][0]["source"] == "hunter_auto_sqli"
    assert Path(state["evidence"][0]["path_or_url"]).exists()


import pytest


@pytest.mark.parametrize(
    ("body", "db_type"),
    [
        ("mysql_fetch_array(): warning", "mysql"),
        ("PostgreSQL pg_query failed", "postgresql"),
        ("Microsoft SQL Server ODBC SQL Server Driver", "mssql"),
        ("ORA-00933 SQL command not properly ended", "oracle"),
        ("SQLite error near sqlite_master", "sqlite"),
    ],
)
def test_database_error_fingerprints(body, db_type):
    from core.sqli_detect import SqliDetector

    assert SqliDetector._database_error(body)[0] == db_type


def test_baseline_database_error_is_not_reported_as_injection():
    from core.sqli_detect import SqliDetector

    session = ScriptedSession(
        lambda method, url, kwargs: Response(500, "ORA-00933 existing application error", {})
    )
    result = SqliDetector(
        "https://target.test/item?id=1",
        param="id",
        session=session,
        technique_memory=RecordingMemory(),
    ).detect()

    assert result["vulnerable"] is False


def test_sqlmap_post_request_includes_session_csrf(monkeypatch):
    import core.auto_sqli as auto_sqli

    captured = {}

    class Completed:
        returncode = 0
        stdout = "done"
        stderr = ""

    def fake_run(command, **kwargs):
        request_path = command[command.index("-r") + 1]
        captured["request"] = Path(request_path).read_text(encoding="utf-8")
        return Completed()

    monkeypatch.setattr(auto_sqli.shutil, "which", lambda name: "sqlmap")
    monkeypatch.setattr(auto_sqli.subprocess, "run", fake_run)
    auto_sqli._run_sqlmap(
        target="https://target.test/search",
        param="q",
        method="POST",
        deep_action="tables",
        csrf_tokens={"csrf_token": "abc123"},
    )

    assert "q=1" in captured["request"]
    assert "csrf_token=abc123" in captured["request"]
