import asyncio
import json

import pytest

import mcp_server
from core.audit import AuditSession
from core.adaptive_engine import get_mode_profile


def test_audit_session_round_trip(tmp_path):
    session = AuditSession("hunter-test", "https://example.test")
    session.status = "completed"
    session.log_event("scan_complete", {"count": 1})
    path = session.save(tmp_path)

    restored = AuditSession.load(path)

    assert restored.session_id == session.session_id
    assert restored.target == session.target
    assert restored.status == "completed"
    assert restored.entries[0].event == "scan_complete"


@pytest.mark.asyncio
async def test_hunter_scan_persists_cancelled_session(monkeypatch, tmp_path):
    mcp_server._sessions.clear()
    monkeypatch.setattr(mcp_server, "SCAN_SESSION_DIR", tmp_path)

    async def cancelled_execute(*args, **kwargs):
        assert len(mcp_server._sessions) == 1
        session = next(iter(mcp_server._sessions.values()))
        assert session.status == "running"
        assert (tmp_path / f"{session.session_id}.json").exists()
        raise asyncio.CancelledError

    monkeypatch.setattr(mcp_server._adaptive_engine, "execute", cancelled_execute)

    with pytest.raises(asyncio.CancelledError):
        await mcp_server.hunter_scan("example.test", mode="standard")

    session = next(iter(mcp_server._sessions.values()))
    assert session.status == "cancelled"
    persisted = json.loads(
        (tmp_path / f"{session.session_id}.json").read_text(encoding="utf-8")
    )
    assert persisted["status"] == "cancelled"


def test_direct_scan_profiles_fit_mcp_transport_budget():
    assert get_mode_profile("fast").wall_time_s < 300
    assert get_mode_profile("standard").wall_time_s < 300
    assert get_mode_profile("deep").wall_time_s < 300


@pytest.mark.asyncio
async def test_session_status_and_report_reload_from_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server, "SCAN_SESSION_DIR", tmp_path)
    session = AuditSession("hunter-restored", "https://example.test", status="completed")
    session.set_report_data([], [], {"agents_completed": 3})
    session.log_event("adaptive_scan_complete", {"agents_completed": 3})
    session.save(tmp_path)
    mcp_server._sessions.clear()

    status = json.loads(await mcp_server.hunter_session_status(session.session_id))
    report = json.loads(await mcp_server.hunter_report(session.session_id, format="json"))

    assert status["status"] == "completed"
    assert status["total_entries"] == 1
    assert report["summary"]["agents_completed"] == 3



@pytest.mark.asyncio
async def test_single_agent_session_is_persisted(monkeypatch, tmp_path):
    mcp_server._sessions.clear()
    monkeypatch.setattr(mcp_server, "SCAN_SESSION_DIR", tmp_path)

    async def success(*args, **kwargs):
        return {"status": "success", "findings": []}

    monkeypatch.setattr(mcp_server, "_execute_agent_async", success)

    result = json.loads(
        await mcp_server._run_single_agent(
            "tech-detect",
            "https://example.test",
        )
    )

    path = tmp_path / f"{result['session_id']}.json"
    assert path.exists()
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["session_id"] == result["session_id"]
    assert persisted["status"] == "completed"
