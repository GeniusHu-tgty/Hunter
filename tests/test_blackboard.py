import hashlib
import json
from pathlib import Path

import core.session.blackboard as blackboard_module
from core.session.blackboard import Blackboard, BoardRegistry


def test_default_storage_directory_matches_project_data_path():
    assert blackboard_module.DEFAULT_STORAGE_DIR == Path(
        r"D:\Open-tgtylab\data\blackboards"
    )


def test_upsert_saves_fact_and_reload_returns_value(tmp_path, monkeypatch):
    timestamps = iter([100.0, 200.0])
    monkeypatch.setattr(blackboard_module.time, "time", lambda: next(timestamps))
    target = "https://target.com/login"
    board = Blackboard(target, storage_dir=tmp_path)

    board.upsert("role", "admin")
    board.upsert("role", "superadmin")

    expected_path = tmp_path / f"{hashlib.sha1(target.encode('utf-8')).hexdigest()}.json"
    assert board.path == expected_path
    assert board.get("role") == "superadmin"
    assert board.get("missing") is None
    assert json.loads(expected_path.read_text(encoding="utf-8")) == {
        "role": {"value": "superadmin", "timestamp": 200.0}
    }
    assert Blackboard(target, storage_dir=tmp_path).get("role") == "superadmin"


def test_list_orders_facts_by_timestamp(tmp_path, monkeypatch):
    timestamps = iter([20.0, 10.0, 30.0])
    monkeypatch.setattr(blackboard_module.time, "time", lambda: next(timestamps))
    board = Blackboard("target.com", storage_dir=tmp_path)

    board.upsert("second", 2)
    board.upsert("first", 1)
    board.upsert("third", 3)

    assert board.list() == [
        ("first", 1, 10.0),
        ("second", 2, 20.0),
        ("third", 3, 30.0),
    ]


def test_as_context_formats_sorted_facts_with_target_hostname(tmp_path, monkeypatch):
    timestamps = iter([20.0, 10.0])
    monkeypatch.setattr(blackboard_module.time, "time", lambda: next(timestamps))
    board = Blackboard("https://target.com:8443/path", storage_dir=tmp_path)
    board.upsert("endpoint", "/admin")
    board.upsert("credential", "admin:secret")

    assert board.as_context() == (
        "[FACTS \u2014 target.com]\n"
        "credential: admin:secret\n"
        "endpoint: /admin"
    )


def test_as_context_is_empty_without_facts(tmp_path):
    assert Blackboard("target.com", storage_dir=tmp_path).as_context() == ""


def test_board_registry_is_global_and_reuses_board_per_target(tmp_path):
    target = "https://registry-target.example"

    first = BoardRegistry.get(target, storage_dir=tmp_path)
    second = BoardRegistry().get(target, storage_dir=tmp_path)

    assert BoardRegistry() is BoardRegistry()
    assert first is second
    first.upsert("status", "confirmed")
    assert second.get("status") == "confirmed"
