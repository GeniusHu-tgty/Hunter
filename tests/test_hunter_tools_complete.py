
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import mcp_server
from core.doctor import HunterDoctor
from core.tool_catalog import classify_tool_inventory


def registered_functions(module):
    return {
        name for name, value in vars(module).items()
        if name.startswith("hunter_") and callable(value)
    }


def extension_names(inventory):
    return {
        name
        for names in inventory["extensions"].values()
        for name in names
    }


def write_inventory_contract(tmp_path, namespaces):
    path = tmp_path / "integration-contract.json"
    path.write_text(
        json.dumps(
            {
                "contract_version": "1.0",
                "server_name": "hunter_tools",
                "minimum_tool_count": 1,
                "required_tools": ["hunter_core"],
                "optional_extension_namespaces": namespaces,
                "workspace_schema_version": "1.0",
            }
        ),
        encoding="utf-8",
    )
    return path


def inventory_for(
    monkeypatch,
    tmp_path,
    names,
    namespaces,
    extension_sources=None,
):
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {name: object() for name in names},
    )
    monkeypatch.setattr(
        mcp_server,
        "INTEGRATION_CONTRACT_PATH",
        write_inventory_contract(tmp_path, namespaces),
        raising=False,
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_SOURCES",
        extension_sources or {},
        raising=False,
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_COLLISIONS",
        [],
        raising=False,
    )
    return mcp_server._registered_tool_inventory()


def test_reverse_lab_candidate_discovery_has_no_unconfigured_defaults():
    assert mcp_server._reverse_lab_tool_candidates({}) == []


def test_reverse_lab_candidate_discovery_uses_configured_paths_in_order(
    tmp_path,
):
    explicit = tmp_path / "custom" / "reverse_lab_tools_mcp.py"
    first_root = tmp_path / "workspace"
    second_root = tmp_path / "other-workspace"
    relative = Path(
        "tools/skills/mcp/ReverseLabToolsMCP/"
        "reverse_lab_tools_mcp.py"
    )

    candidates = mcp_server._reverse_lab_tool_candidates(
        {
            "REVERSELAB_MCP_PATH": str(explicit),
            "OPEN_TGTYLAB_ROOT": str(first_root),
            "OPEN_TGTYLAB_WORKSPACE": str(first_root / "."),
            "TGTYLAB_ROOT": str(second_root),
        }
    )

    assert candidates == [
        explicit.resolve(),
        (first_root / relative).resolve(),
        (second_root / relative).resolve(),
    ]


def test_reverse_lab_candidate_discovery_ignores_relative_values_across_cwd(
    monkeypatch,
    tmp_path,
):
    environment = {
        "REVERSELAB_MCP_PATH": "relative/reverse_lab_tools_mcp.py",
        "OPEN_TGTYLAB_ROOT": "relative-workspace",
    }
    first_cwd = tmp_path / "first"
    second_cwd = tmp_path / "second"
    first_cwd.mkdir()
    second_cwd.mkdir()

    monkeypatch.chdir(first_cwd)
    first = mcp_server._reverse_lab_tool_candidates(environment)
    monkeypatch.chdir(second_cwd)
    second = mcp_server._reverse_lab_tool_candidates(environment)

    assert first == second == []


def test_reverse_lab_candidate_discovery_expands_user_before_absolute_check(
    monkeypatch,
    tmp_path,
):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    configured = Path("~/reverse-lab/reverse_lab_tools_mcp.py")

    candidates = mcp_server._reverse_lab_tool_candidates(
        {"REVERSELAB_MCP_PATH": str(configured)}
    )

    assert candidates == [configured.expanduser().resolve()]


def test_reverse_lab_import_is_idempotent_and_restores_sys_path(
    monkeypatch,
    tmp_path,
):
    extension_dir = tmp_path / "extension"
    extension_dir.mkdir()
    helper_name = f"reverse_lab_helper_{os.getpid()}_{id(tmp_path)}"
    (extension_dir / f"{helper_name}.py").write_text(
        "from types import SimpleNamespace\n"
        "TOOL = SimpleNamespace(name='fixture')\n",
        encoding="utf-8",
    )
    counter_path = extension_dir / "execution-count.txt"
    reverse_lab_path = extension_dir / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text(
        "from pathlib import Path\n"
        "from types import SimpleNamespace\n"
        f"from {helper_name} import TOOL\n"
        "_counter = Path(__file__).with_name('execution-count.txt')\n"
        "_count = int(_counter.read_text() or '0') "
        "if _counter.exists() else 0\n"
        "_counter.write_text(str(_count + 1))\n"
        "mcp = SimpleNamespace(\n"
        "    _tool_manager=SimpleNamespace(_tools={'fixture': TOOL})\n"
        ")\n",
        encoding="utf-8",
    )
    baseline_sys_path = list(mcp_server.sys.path)
    monkeypatch.setattr(mcp_server.sys, "path", list(baseline_sys_path))
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {"hunter_core": object()},
    )
    monkeypatch.setattr(mcp_server, "_EXTENSION_TOOL_SOURCES", {})
    monkeypatch.setattr(
        mcp_server,
        "_REVERSE_LAB_MODULE_CACHE",
        {},
        raising=False,
    )
    monkeypatch.setenv("REVERSELAB_MCP_PATH", str(reverse_lab_path))
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    try:
        mcp_server._import_reverse_lab_tools()
        first_tool = mcp_server.mcp._tool_manager._tools["re_fixture"]
        assert mcp_server.sys.path == baseline_sys_path
        assert counter_path.read_text(encoding="utf-8") == "1"

        monkeypatch.setattr(
            mcp_server.mcp._tool_manager,
            "_tools",
            {"hunter_core": object()},
        )
        monkeypatch.setattr(mcp_server, "_EXTENSION_TOOL_SOURCES", {})
        mcp_server._import_reverse_lab_tools()

        assert (
            mcp_server.mcp._tool_manager._tools["re_fixture"]
            is first_tool
        )
        assert mcp_server.sys.path == baseline_sys_path
        assert counter_path.read_text(encoding="utf-8") == "1"
        assert mcp_server._EXTENSION_TOOL_SOURCES == {
            "reverse_lab_tools": {"re_fixture"},
        }
        assert list(mcp_server._REVERSE_LAB_MODULE_CACHE) == [
            reverse_lab_path.resolve()
        ]
    finally:
        mcp_server.sys.modules.pop(helper_name, None)


def test_reverse_lab_import_registers_module_before_dataclass_execution(
    monkeypatch,
    tmp_path,
):
    reverse_lab_path = tmp_path / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text(
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n"
        "from types import SimpleNamespace\n"
        "@dataclass\n"
        "class Fixture:\n"
        "    child: Fixture | None = None\n"
        "TOOL = SimpleNamespace(name='fixture')\n"
        "mcp = SimpleNamespace(\n"
        "    _tool_manager=SimpleNamespace(_tools={'fixture': TOOL})\n"
        ")\n",
        encoding="utf-8",
    )
    resolved_path = reverse_lab_path.resolve()
    module_name = (
        "_hunter_reverselab_"
        + hashlib.sha256(
            os.path.normcase(str(resolved_path)).encode("utf-8")
        ).hexdigest()
    )
    baseline_sys_path = list(mcp_server.sys.path)
    monkeypatch.setattr(mcp_server.sys, "path", list(baseline_sys_path))
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {"hunter_core": object()},
    )
    monkeypatch.setattr(mcp_server, "_EXTENSION_TOOL_SOURCES", {})
    monkeypatch.setattr(
        mcp_server,
        "_REVERSE_LAB_MODULE_CACHE",
        {},
        raising=False,
    )
    monkeypatch.setenv("REVERSELAB_MCP_PATH", str(reverse_lab_path))
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    try:
        mcp_server._import_reverse_lab_tools()

        cached_module = mcp_server._REVERSE_LAB_MODULE_CACHE[
            resolved_path
        ]
        assert mcp_server.sys.modules[module_name] is cached_module
        assert "re_fixture" in mcp_server.mcp._tool_manager._tools
        assert mcp_server.sys.path == baseline_sys_path
    finally:
        mcp_server.sys.modules.pop(module_name, None)


def test_reverse_lab_import_failure_rolls_back_module_and_allows_retry(
    monkeypatch,
    tmp_path,
):
    attempts_path = tmp_path / "attempts.txt"
    reverse_lab_path = tmp_path / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text(
        "from __future__ import annotations\n"
        "from pathlib import Path\n"
        "from types import SimpleNamespace\n"
        "_attempts = Path(__file__).with_name('attempts.txt')\n"
        "_count = int(_attempts.read_text() or '0') "
        "if _attempts.exists() else 0\n"
        "_attempts.write_text(str(_count + 1))\n"
        "if _count == 0:\n"
        "    raise RuntimeError('retry fixture')\n"
        "from dataclasses import dataclass\n"
        "@dataclass\n"
        "class Fixture:\n"
        "    child: Fixture | None = None\n"
        "TOOL = SimpleNamespace(name='fixture')\n"
        "mcp = SimpleNamespace(\n"
        "    _tool_manager=SimpleNamespace(_tools={'fixture': TOOL})\n"
        ")\n",
        encoding="utf-8",
    )
    resolved_path = reverse_lab_path.resolve()
    module_name = (
        "_hunter_reverselab_"
        + hashlib.sha256(
            os.path.normcase(str(resolved_path)).encode("utf-8")
        ).hexdigest()
    )
    baseline_sys_path = list(mcp_server.sys.path)
    monkeypatch.setattr(mcp_server.sys, "path", list(baseline_sys_path))
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {"hunter_core": object()},
    )
    monkeypatch.setattr(mcp_server, "_EXTENSION_TOOL_SOURCES", {})
    monkeypatch.setattr(
        mcp_server,
        "_REVERSE_LAB_MODULE_CACHE",
        {},
        raising=False,
    )
    monkeypatch.setenv("REVERSELAB_MCP_PATH", str(reverse_lab_path))
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    try:
        mcp_server._import_reverse_lab_tools()

        assert module_name not in mcp_server.sys.modules
        assert resolved_path not in mcp_server._REVERSE_LAB_MODULE_CACHE
        assert mcp_server.sys.path == baseline_sys_path

        mcp_server._import_reverse_lab_tools()

        cached_module = mcp_server._REVERSE_LAB_MODULE_CACHE[
            resolved_path
        ]
        assert mcp_server.sys.modules[module_name] is cached_module
        assert attempts_path.read_text(encoding="utf-8") == "2"
        assert "re_fixture" in mcp_server.mcp._tool_manager._tools
        assert mcp_server.sys.path == baseline_sys_path
    finally:
        mcp_server.sys.modules.pop(module_name, None)


@pytest.mark.parametrize(
    "outcome",
    ["missing_spec", "load_failure", "missing_tool_manager"],
)
def test_reverse_lab_import_restores_sys_path_on_all_early_returns(
    monkeypatch,
    tmp_path,
    outcome,
):
    reverse_lab_path = tmp_path / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text("# import fixture\n", encoding="utf-8")
    baseline_sys_path = list(mcp_server.sys.path)
    monkeypatch.setattr(mcp_server.sys, "path", list(baseline_sys_path))
    monkeypatch.setattr(
        mcp_server,
        "_REVERSE_LAB_MODULE_CACHE",
        {},
        raising=False,
    )
    monkeypatch.setenv("REVERSELAB_MCP_PATH", str(reverse_lab_path))
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    if outcome == "missing_spec":
        monkeypatch.setattr(
            importlib.util,
            "spec_from_file_location",
            lambda *_args, **_kwargs: None,
        )
    else:
        class Loader:
            @staticmethod
            def exec_module(module):
                if outcome == "load_failure":
                    raise RuntimeError("fixture load failure")
                module.mcp = SimpleNamespace()

        monkeypatch.setattr(
            importlib.util,
            "spec_from_file_location",
            lambda *_args, **_kwargs: SimpleNamespace(loader=Loader()),
        )
        monkeypatch.setattr(
            importlib.util,
            "module_from_spec",
            lambda _spec: SimpleNamespace(),
        )

    mcp_server._import_reverse_lab_tools()

    assert mcp_server.sys.path == baseline_sys_path
    if outcome in {"missing_spec", "load_failure"}:
        assert mcp_server._REVERSE_LAB_MODULE_CACHE == {}
    else:
        assert list(mcp_server._REVERSE_LAB_MODULE_CACHE) == [
            reverse_lab_path.resolve()
        ]


def test_reverse_lab_import_module_names_are_unique_per_resolved_path(
    monkeypatch,
    tmp_path,
):
    first_path = tmp_path / "first" / "reverse_lab_tools_mcp.py"
    second_path = tmp_path / "second" / "reverse_lab_tools_mcp.py"
    for path in (first_path, second_path):
        path.parent.mkdir()
        path.write_text(
            "from types import SimpleNamespace\n"
            "mcp = SimpleNamespace(\n"
            "    _tool_manager=SimpleNamespace(_tools={})\n"
            ")\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(
        mcp_server,
        "_REVERSE_LAB_MODULE_CACHE",
        {},
        raising=False,
    )
    monkeypatch.setattr(mcp_server.sys, "path", list(mcp_server.sys.path))
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    for path in (first_path, second_path):
        monkeypatch.setenv("REVERSELAB_MCP_PATH", str(path))
        mcp_server._import_reverse_lab_tools()

    module_names = {
        module.__name__
        for module in mcp_server._REVERSE_LAB_MODULE_CACHE.values()
    }
    assert module_names == {
        "_hunter_reverselab_"
        + hashlib.sha256(
            os.path.normcase(str(path.resolve())).encode("utf-8")
        ).hexdigest()
        for path in (first_path, second_path)
    }


def test_imported_reverse_lab_tools_remain_source_attributed(
    monkeypatch,
    tmp_path,
):
    reverse_lab_path = tmp_path / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text("# import fixture\n", encoding="utf-8")
    reverse_tools = {
        f"tool_{index}": SimpleNamespace(name=f"tool_{index}")
        for index in range(105)
    }
    reverse_mcp = SimpleNamespace(
        _tool_manager=SimpleNamespace(_tools=reverse_tools)
    )

    class Loader:
        @staticmethod
        def exec_module(module):
            module.mcp = reverse_mcp

    monkeypatch.setattr(
        importlib.util,
        "spec_from_file_location",
        lambda *_args, **_kwargs: SimpleNamespace(loader=Loader()),
    )
    monkeypatch.setattr(
        importlib.util,
        "module_from_spec",
        lambda _spec: SimpleNamespace(),
    )
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {"hunter_core": object()},
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_SOURCES",
        {},
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_COLLISIONS",
        [],
        raising=False,
    )
    monkeypatch.setattr(
        mcp_server,
        "INTEGRATION_CONTRACT_PATH",
        write_inventory_contract(tmp_path, ["re_"]),
    )
    monkeypatch.setattr(
        mcp_server.sys,
        "path",
        list(mcp_server.sys.path),
    )
    monkeypatch.setenv(
        "REVERSELAB_MCP_PATH",
        str(reverse_lab_path),
    )
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    mcp_server._import_reverse_lab_tools()
    inventory = mcp_server._registered_tool_inventory()

    assert len(
        inventory["extensions"]["reverse_lab_tools"]
    ) == 105
    assert set(
        inventory["extensions"]["reverse_lab_tools"]
    ) == {
        f"re_tool_{index}"
        for index in range(105)
    }
    assert inventory["counts"] == {
        "core": 1,
        "extensions": 105,
        "unknown": 0,
        "total": 106,
    }


def test_reverse_lab_import_does_not_claim_existing_registry_collision(
    monkeypatch,
    tmp_path,
):
    reverse_lab_path = tmp_path / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text("# import fixture\n", encoding="utf-8")
    original_collision = SimpleNamespace(name="re_collision")
    reverse_collision = SimpleNamespace(name="collision")
    reverse_fresh = SimpleNamespace(name="fresh")
    reverse_mcp = SimpleNamespace(
        _tool_manager=SimpleNamespace(
            _tools={
                "collision": reverse_collision,
                "fresh": reverse_fresh,
            }
        )
    )

    class Loader:
        @staticmethod
        def exec_module(module):
            module.mcp = reverse_mcp

    monkeypatch.setattr(
        importlib.util,
        "spec_from_file_location",
        lambda *_args, **_kwargs: SimpleNamespace(loader=Loader()),
    )
    monkeypatch.setattr(
        importlib.util,
        "module_from_spec",
        lambda _spec: SimpleNamespace(),
    )
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {
            "hunter_core": object(),
            "re_collision": original_collision,
        },
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_SOURCES",
        {},
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_COLLISIONS",
        [],
    )
    monkeypatch.setattr(
        mcp_server,
        "INTEGRATION_CONTRACT_PATH",
        write_inventory_contract(tmp_path, ["re_"]),
    )
    monkeypatch.setattr(
        mcp_server.sys,
        "path",
        list(mcp_server.sys.path),
    )
    monkeypatch.setenv(
        "REVERSELAB_MCP_PATH",
        str(reverse_lab_path),
    )
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    mcp_server._import_reverse_lab_tools()
    mcp_server._import_reverse_lab_tools()
    inventory = mcp_server._registered_tool_inventory()
    health = json.loads(asyncio.run(mcp_server.hunter_healthcheck()))
    capabilities = json.loads(
        asyncio.run(mcp_server.hunter_capabilities())
    )
    runtime = json.loads(
        asyncio.run(mcp_server.hunter_runtime_status())
    )
    doctor = json.loads(asyncio.run(mcp_server.hunter_doctor()))
    contract = json.loads(
        asyncio.run(mcp_server.hunter_contract_check())
    )

    registry = mcp_server.mcp._tool_manager._tools
    expected_collisions = [
        {
            "tool": "re_collision",
            "sources": [
                "contract_extensions",
                "reverse_lab_tools",
            ],
        }
    ]
    assert registry["re_collision"] is original_collision
    assert registry["re_fresh"] is reverse_fresh
    assert inventory["extensions"]["reverse_lab_tools"] == [
        "re_fresh",
    ]
    assert inventory["extensions"]["contract_extensions"] == [
        "re_collision",
    ]
    assert inventory["collisions"] == expected_collisions
    assert inventory["collision_count"] == 1
    assert inventory["counts"]["total"] == len(registry)
    assert health["mcp_tools"]["collisions"] == expected_collisions
    assert capabilities["collisions"] == expected_collisions
    assert runtime["data"]["collisions"] == expected_collisions
    assert doctor["status"] == "degraded"
    assert doctor["data"]["collisions"] == expected_collisions
    assert (
        doctor["data"]["checks"]["contract"]["data"]["collisions"]
        == expected_collisions
    )
    assert contract["status"] == "error"
    assert contract["data"]["collisions"] == expected_collisions


def test_reverse_lab_collision_uses_current_source_map_and_is_stable(
    monkeypatch,
    tmp_path,
):
    reverse_lab_path = tmp_path / "reverse_lab_tools_mcp.py"
    reverse_lab_path.write_text("# import fixture\n", encoding="utf-8")
    original_collision = SimpleNamespace(name="re_collision")
    incoming_collision = SimpleNamespace(name="collision")
    reverse_mcp = SimpleNamespace(
        _tool_manager=SimpleNamespace(
            _tools={"collision": incoming_collision}
        )
    )

    class Loader:
        @staticmethod
        def exec_module(module):
            module.mcp = reverse_mcp

    monkeypatch.setattr(
        importlib.util,
        "spec_from_file_location",
        lambda *_args, **_kwargs: SimpleNamespace(loader=Loader()),
    )
    monkeypatch.setattr(
        importlib.util,
        "module_from_spec",
        lambda _spec: SimpleNamespace(),
    )
    monkeypatch.setattr(
        mcp_server.mcp._tool_manager,
        "_tools",
        {
            "hunter_core": object(),
            "re_collision": original_collision,
        },
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_SOURCES",
        {
            "z_source": {"re_collision"},
            "a_source": {"re_collision"},
        },
    )
    monkeypatch.setattr(
        mcp_server,
        "_EXTENSION_TOOL_COLLISIONS",
        [],
    )
    monkeypatch.setattr(
        mcp_server,
        "_REVERSE_LAB_MODULE_CACHE",
        {},
    )
    monkeypatch.setattr(
        mcp_server,
        "INTEGRATION_CONTRACT_PATH",
        write_inventory_contract(tmp_path, ["re_"]),
    )
    monkeypatch.setattr(
        mcp_server.sys,
        "path",
        list(mcp_server.sys.path),
    )
    monkeypatch.setenv(
        "REVERSELAB_MCP_PATH",
        str(reverse_lab_path),
    )
    for name in mcp_server._REVERSE_LAB_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    mcp_server._import_reverse_lab_tools()
    first = mcp_server._registered_tool_inventory()
    mcp_server._import_reverse_lab_tools()
    second = mcp_server._registered_tool_inventory()

    expected = [
        {
            "tool": "re_collision",
            "sources": [
                "a_source",
                "reverse_lab_tools",
                "z_source",
            ],
        }
    ]
    assert mcp_server.mcp._tool_manager._tools["re_collision"] is original_collision
    assert "re_collision" not in mcp_server._EXTENSION_TOOL_SOURCES[
        "reverse_lab_tools"
    ]
    assert first["collisions"] == expected
    assert first["collision_count"] == 1
    assert second["collisions"] == expected
    assert second["collision_count"] == 1
    assert first["counts"]["total"] == 2


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
    extensions = extension_names(inventory)
    unknown = set(inventory["unknown"])
    core = set(inventory["core"])
    assert inventory["unknown"] == []
    assert core == functions
    assert core.isdisjoint(extensions)
    assert core.isdisjoint(unknown)
    assert extensions.isdisjoint(unknown)
    assert core | extensions | unknown == registry
    assert inventory["counts"]["total"] == len(registry)
    assert len(functions) == 114
    reverse_lab_source = set(
        mcp_server._EXTENSION_TOOL_SOURCES.get(
            "reverse_lab_tools",
            (),
        )
    )
    if reverse_lab_source:
        assert set(
            inventory["extensions"]["reverse_lab_tools"]
        ) == reverse_lab_source


def test_registered_tool_inventory_without_extensions_is_deterministic(
    monkeypatch,
    tmp_path,
):
    inventory = inventory_for(
        monkeypatch,
        tmp_path,
        names=["hunter_core"],
        namespaces=["re_"],
    )
    assert inventory == {
        "core": ["hunter_core"],
        "extensions": {},
        "unknown": [],
        "invalid_extension_tools": [],
        "collisions": [],
        "collision_count": 0,
        "counts": {
            "core": 1,
            "extensions": 0,
            "unknown": 0,
            "total": 1,
        },
    }


def test_registered_tool_inventory_separates_core_and_extensions(
    monkeypatch,
    tmp_path,
):
    inventory = inventory_for(
        monkeypatch,
        tmp_path,
        names=["hunter_core", "re_triage_pe"],
        namespaces=["re_"],
    )
    assert inventory["core"] == ["hunter_core"]
    assert inventory["extensions"] == {
        "contract_extensions": ["re_triage_pe"],
    }
    assert inventory["unknown"] == []
    assert inventory["counts"]["total"] == 2


def test_registered_tool_inventory_resolves_extension_source_overlap(
    monkeypatch,
    tmp_path,
):
    names = {
        "hunter_core",
        "re_shared",
        "re_source_only",
        "re_contract_only",
        "plugin_source_only",
        "invalid_extension",
        "unclassified_tool",
    }
    sources = {
        "z_source": {
            "hunter_core",
            "re_shared",
            "re_source_only",
            "invalid_extension",
        },
        "a_source": {
            "re_shared",
            "plugin_source_only",
        },
    }

    first = inventory_for(
        monkeypatch,
        tmp_path,
        names=names,
        namespaces=["re_", "plugin_"],
        extension_sources=sources,
    )
    second = mcp_server._registered_tool_inventory()
    core = set(first["core"])
    extensions = extension_names(first)
    unknown = set(first["unknown"])

    assert first == second
    assert first["extensions"] == {
        "a_source": ["plugin_source_only"],
        "contract_extensions": [
            "re_contract_only",
            "re_shared",
        ],
        "z_source": ["re_source_only"],
    }
    assert first["collisions"] == [
        {
            "tool": "re_shared",
            "sources": ["a_source", "z_source"],
        }
    ]
    assert first["collision_count"] == 1
    assert unknown == {
        "invalid_extension",
        "unclassified_tool",
    }
    assert core.isdisjoint(extensions)
    assert core.isdisjoint(unknown)
    assert extensions.isdisjoint(unknown)
    assert core | extensions | unknown == names
    assert first["counts"] == {
        "core": 1,
        "extensions": 4,
        "unknown": 2,
        "total": len(names),
    }


def test_classify_tool_inventory_merges_and_deduplicates_collisions():
    inventory, invalid = classify_tool_inventory(
        core_tools=["hunter_core"],
        extension_tools={
            "z_source": ["re_shared", "invalid_shared"],
            "a_source": ["re_shared", "invalid_shared"],
            "solo_source": ["re_solo"],
        },
        optional_extension_namespaces=["re_"],
        declared_collisions=[
            {
                "tool": "re_shared",
                "sources": ["z_source", "a_source"],
            },
            {
                "tool": "re_shared",
                "sources": ["loader_source", "a_source"],
            },
            {
                "tool": "re_loader",
                "existing_sources": ["contract_extensions"],
                "incoming_source": "reverse_lab_tools",
            },
            {
                "tool": "re_loader",
                "sources": [
                    "reverse_lab_tools",
                    "contract_extensions",
                ],
            },
        ],
    )

    assert inventory["extensions"] == {
        "contract_extensions": ["re_shared"],
        "solo_source": ["re_solo"],
    }
    assert inventory["unknown"] == ["invalid_shared"]
    assert invalid == ["invalid_shared"]
    assert inventory["collisions"] == [
        {
            "tool": "invalid_shared",
            "sources": ["a_source", "z_source"],
        },
        {
            "tool": "re_loader",
            "sources": [
                "contract_extensions",
                "reverse_lab_tools",
            ],
        },
        {
            "tool": "re_shared",
            "sources": [
                "a_source",
                "loader_source",
                "z_source",
            ],
        },
    ]
    assert inventory["collision_count"] == 3
    assert inventory["counts"] == {
        "core": 1,
        "extensions": 2,
        "unknown": 1,
        "total": 4,
    }


def test_registered_tool_inventory_uses_contract_extension_prefixes(
    monkeypatch,
    tmp_path,
):
    inventory = inventory_for(
        monkeypatch,
        tmp_path,
        names=["hunter_core", "plugin_triage"],
        namespaces=["plugin_"],
    )
    assert inventory["extensions"] == {
        "contract_extensions": ["plugin_triage"],
    }
    assert inventory["unknown"] == []


def test_registered_tool_inventory_classifies_unknown_tools(
    monkeypatch,
    tmp_path,
):
    inventory = inventory_for(
        monkeypatch,
        tmp_path,
        names=["hunter_core", "unclassified_tool"],
        namespaces=["re_", "plugin_"],
    )
    assert inventory["core"] == ["hunter_core"]
    assert inventory["extensions"] == {}
    assert inventory["unknown"] == ["unclassified_tool"]
    assert inventory["counts"] == {
        "core": 1,
        "extensions": 0,
        "unknown": 1,
        "total": 2,
    }


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
    assert len(contract["required_tools"]) == 114
    assert contract["minimum_tool_count"] == 114
    assert contract["exact_core_tool_count"] == 114
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
    root = os.environ.get("OPEN_TGTYLAB_ROOT")
    if not root:
        pytest.skip("OPEN_TGTYLAB_ROOT is not configured")
    path = Path(root).expanduser() / ".mcp.json"
    if not path.is_file():
        pytest.skip(f"project MCP config does not exist: {path}")
    config = json.loads(path.read_text(encoding="utf-8"))
    servers = config["mcpServers"]
    assert "hunter" not in servers
    assert servers["hunter_tools"]["args"][-1].replace("\\", "/").endswith("/hunter/mcp_server.py")


def test_codex_configs_have_only_hunter_tools():
    import tomllib
    paths = [Path.home() / ".codex" / "config.toml"]
    root = os.environ.get("OPEN_TGTYLAB_ROOT")
    if root:
        paths.insert(
            0,
            Path(root).expanduser() / ".codex" / "config.toml",
        )
    paths = [path for path in paths if path.is_file()]
    if not paths:
        pytest.skip("no real Codex config files are available")
    for path in paths:
        config = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        servers = config.get("mcp_servers", {})
        assert "hunter" not in servers
        assert "hunter_tools" in servers
        assert servers["hunter_tools"]["args"][-1].replace("\\", "/").endswith("/hunter/mcp_server.py")


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        (
            ".mcp.json",
            json.dumps(
                {
                    "mcpServers": {
                        "hunter_tools": {
                            "command": "python",
                            "args": ["hunter/mcp_server.py"],
                        }
                    }
                }
            ),
        ),
        (
            "config.toml",
            '[mcp_servers.hunter_tools]\n'
            'command = "python"\n'
            'args = ["hunter/mcp_server.py"]\n',
        ),
    ],
)
def test_temporary_config_registration_parsing(
    tmp_path,
    filename,
    content,
):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")

    registrations, error = HunterDoctor._registrations(path)

    assert error is None
    assert registrations == {"hunter_tools"}


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
