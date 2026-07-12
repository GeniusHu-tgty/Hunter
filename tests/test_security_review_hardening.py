import asyncio
import json
from pathlib import Path

import pytest

import mcp_server
from core.session import AttackSession
from core.stealth.stealth_http_client import StealthHTTPClient


def test_chain_mcp_propagates_approval_required_status(tmp_path, monkeypatch):
    session = mcp_server._reset_attack_session_store(tmp_path).create(
        "https://example.test",
        session_id="approval",
    )

    class FakeChain:
        def execute(self, session, params=None):
            return {"status": "approval-required", "pending": {"step_id": "exploit"}}

    monkeypatch.setattr(mcp_server, "_resolve_attack_chain", lambda name: Path(__file__))
    monkeypatch.setattr(mcp_server.AttackChain, "load", lambda *args, **kwargs: FakeChain())
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(session.session_id, "approval")
    ))
    assert result["status"] == "approval-required"


def test_private_js_analysis_requires_operator_environment(monkeypatch):
    monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_JS_ANALYSIS", raising=False)
    with pytest.raises(PermissionError):
        mcp_server._validate_js_analysis_url("http://127.0.0.1/app.js", allow_private=True)
    monkeypatch.setenv("HUNTER_ALLOW_PRIVATE_JS_ANALYSIS", "1")
    mcp_server._validate_js_analysis_url("http://127.0.0.1/app.js", allow_private=True)


def test_js_endpoint_resolution_returns_validated_connection_ip(monkeypatch):
    monkeypatch.setattr(
        mcp_server.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    parsed, address, port = mcp_server._resolve_js_analysis_endpoint("https://example.test/app.js")
    assert parsed.hostname == "example.test"
    assert address == "93.184.216.34"
    assert port == 443


def test_attack_http_client_does_not_persist_cookie_or_csrf(tmp_path):
    client = StealthHTTPClient(tmp_path, persist_secrets=False)
    state = {
        "target": "https://example.test:443",
        "cookies": {"sid": "secret-cookie"},
        "csrf_tokens": {"csrf": "secret-token"},
    }
    client._save(state)
    serialized = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    assert "secret-cookie" not in serialized
    assert "secret-token" not in serialized


def test_attack_request_executor_disables_redirects(monkeypatch, tmp_path):
    session = AttackSession("https://example.test", storage_dir=tmp_path)
    captured = {}

    class FakeClient:
        def stealth_request(self, method, url, headers=None, data=None, options=None):
            captured.update(options or {})
            return {"status": "ok", "status_code": 200, "url": url, "headers": {}, "body": ""}

    monkeypatch.setattr(mcp_server, "_sync_attack_http_client", lambda session: FakeClient())
    mcp_server._attack_request_executor(
        session,
        {"method": "GET", "url": "https://example.test/path", "headers": {}, "data": None, "options": {}},
    )
    assert captured["follow_redirects"] is False
