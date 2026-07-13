import asyncio
import json

import mcp_server
from core.browser.browser_controller import BrowserController, ExecutionAdapter


def test_execution_adapter_forwards_calls_and_converts_failures_to_errors():
    seen = []

    async def caller(server_name, tool_name, arguments):
        seen.append((server_name, tool_name, arguments))
        if tool_name == "browser_click":
            raise RuntimeError("page has been closed")
        return {"value": "ok"}

    adapter = ExecutionAdapter(caller)
    success = asyncio.run(adapter.execute_call("browser_snapshot", {}))
    failure = asyncio.run(
        adapter.execute_call("browser_click", {"target": {"text": "Save"}})
    )

    assert success == {"value": "ok"}
    assert failure == {"error": "page has been closed"}
    assert seen[0] == ("playwright-mcp", "browser_snapshot", {})


def test_execution_adapter_recognizes_mcp_error_envelopes_and_runs_failure_calls():
    seen = []

    async def caller(server_name, tool_name, arguments):
        seen.append(tool_name)
        if tool_name == "browser_click":
            return {
                "isError": True,
                "content": [{"type": "text", "text": "target page is closed"}],
            }
        return {"ok": True}

    controller = BrowserController(call_mcp_tool=caller)
    result = asyncio.run(
        controller.click_and_capture(
            {"text": "Save"},
            execute=True,
        )
    )

    assert result["status"] == "error"
    assert "target page is closed" in result["error"]
    assert "browser_take_screenshot" in seen
    assert "browser_console_messages" in seen
    assert result["failure_results"]


def test_execute_true_without_adapter_keeps_deferred_behavior():
    controller = BrowserController()

    plan = controller.navigate_and_wait(
        "https://example.test/app",
        execute=True,
    )

    assert isinstance(plan, dict)
    assert plan["status"] == "proposed"
    assert plan["execution"] == "deferred"
    assert plan["calls"][0]["tool"] == "browser_navigate"


def test_navigation_execute_merges_page_summary_and_classifies_timeout():
    calls = []

    async def caller(server_name, tool_name, arguments):
        calls.append((server_name, tool_name, arguments))
        if tool_name == "browser_evaluate":
            return {
                "url": "https://example.test/app",
                "title": "Research Portal",
                "html_length": 2048,
                "has_form": True,
                "has_login": True,
                "has_websocket": False,
            }
        return {"ok": True}

    controller = BrowserController(call_mcp_tool=caller)
    result = asyncio.run(
        controller.navigate_and_wait(
            "https://example.test/app",
            {"network_idle": True},
            execute=True,
        )
    )

    assert result["status"] == "ok"
    assert result["execution"] == "completed"
    assert result["title"] == "Research Portal"
    assert result["html_length"] == 2048
    assert result["has_form"] is True
    assert [item[1] for item in calls][-1] == "browser_evaluate"

    async def timeout_caller(server_name, tool_name, arguments):
        raise asyncio.TimeoutError("navigation timed out")

    timeout_controller = BrowserController(call_mcp_tool=timeout_caller)
    timeout = asyncio.run(
        timeout_controller.navigate_and_wait(
            "https://example.test/slow",
            execute=True,
        )
    )

    assert timeout["status"] == "timeout"
    assert "timed out" in timeout["error"]


def test_navigation_execute_recursively_unwraps_summary_and_parses_booleans():
    async def caller(server_name, tool_name, arguments):
        if tool_name == "browser_evaluate":
            return {
                "structuredContent": {
                    "data": {
                        "url": "https://example.test/nested",
                        "title": "Nested",
                        "html_length": "321",
                        "has_form": "false",
                        "has_login": "0",
                        "has_websocket": "true",
                    }
                }
            }
        return {"ok": True}

    controller = BrowserController(call_mcp_tool=caller)
    result = asyncio.run(
        controller.navigate_and_wait(
            "https://example.test/nested",
            execute=True,
        )
    )

    assert result["status"] == "ok"
    assert result["html_length"] == 321
    assert result["has_form"] is False
    assert result["has_login"] is False
    assert result["has_websocket"] is True


def test_hook_execution_confirms_each_hook_and_detects_navigation_change():
    current_url = "https://example.test/app"

    async def caller(server_name, tool_name, arguments):
        nonlocal current_url
        assert tool_name == "browser_evaluate"
        if "storage-marker" in arguments["function"]:
            current_url = "https://example.test/next"
        return {"url": current_url, "installed": True}

    controller = BrowserController(call_mcp_tool=caller)
    result = asyncio.run(
        controller.inject_hooks(
            {
                "fetch": "window.__hunterHooks = {fetch: true};",
                "storage": "window.__hunterHooks.storage = 'storage-marker';",
            },
            expected_url="https://example.test/app",
            execute=True,
        )
    )

    assert [item["hook"] for item in result["hook_statuses"]] == [
        "fetch",
        "storage",
    ]
    assert all(item["status"] == "installed" for item in result["hook_statuses"])
    assert result["status"] == "navigation_changed"
    assert result["current_url"] == "https://example.test/next"


def test_hook_execution_requires_confirmation_and_latches_intermediate_navigation():
    urls = iter(
        [
            "https://example.test/",
            "https://example.test/next",
            "https://example.test",
        ]
    )

    async def caller(server_name, tool_name, arguments):
        return {"url": next(urls)}

    controller = BrowserController(call_mcp_tool=caller)
    result = asyncio.run(
        controller.inject_hooks(
            {
                "fetch": "window.__hunterHooks = {fetch: true};",
                "storage": "window.__hunterHooks.storage = true;",
                "crypto": "window.__hunterHooks.crypto = true;",
            },
            expected_url="https://example.test",
            execute=True,
        )
    )

    assert result["hook_statuses"][0]["status"] == "unconfirmed"
    assert result["status"] == "navigation_changed"
    assert result["current_url"] == "https://example.test"


def test_hook_console_execution_classifies_prefixed_records():
    messages = [
        "ordinary console output",
        '__HUNTER_HOOK__{"hook":"fetch","phase":"request","url":"/api"}',
        '__HUNTER_HOOK__{"hook":"crypto","method":"digest"}',
        '__HUNTER_HOOK__{"hook":"storage","operation":"setItem"}',
        '__HUNTER_HOOK__{"hook":"cookie","operation":"write"}',
        '__HUNTER_HOOK__{"hook":"websocket","direction":"received","data":"ok"}',
    ]

    async def caller(server_name, tool_name, arguments):
        assert tool_name == "browser_console_logs"
        return {"logs": messages}

    controller = BrowserController(call_mcp_tool=caller)
    result = asyncio.run(controller.get_hook_results(execute=True))

    assert result["accepted"] == 5
    assert len(result["network_requests"]) == 1
    assert len(result["crypto_operations"]) == 1
    assert len(result["storage_operations"]) == 2
    assert len(result["websocket_messages"]) == 1


def test_browser_mcp_execute_mode_uses_configured_caller(tmp_path):
    async def caller(server_name, tool_name, arguments):
        if tool_name == "browser_console_logs":
            return {
                "logs": [
                    '__HUNTER_HOOK__{"hook":"xhr","phase":"request","url":"/api"}'
                ]
            }
        if tool_name == "browser_evaluate":
            if "__hunterHooks" in arguments["function"]:
                return {
                    "url": "https://example.test/app",
                    "installed": True,
                }
            return {
                "url": "https://example.test/app",
                "title": "Portal",
                "html_length": 100,
                "has_form": False,
                "has_login": False,
                "has_websocket": True,
            }
        return {"ok": True}

    mcp_server._reset_browser_store(tmp_path)
    mcp_server._set_browser_mcp_caller(caller)
    try:
        navigate = json.loads(
            asyncio.run(
                mcp_server.hunter_browser_navigate(
                    "https://example.test/app",
                    execute=True,
                )
            )
        )
        session_id = navigate["data"]["browser_session_id"]

        assert navigate["status"] == "ok"
        assert navigate["data"]["target_url"] == "https://example.test/app"
        assert navigate["data"]["title"] == "Portal"
        assert navigate["data"]["has_websocket"] is True

        hooks = json.loads(
            asyncio.run(
                mcp_server.hunter_browser_inject_hooks(
                    browser_session_id=session_id,
                    hooks=["fetch"],
                    execute=True,
                )
            )
        )
        assert hooks["status"] == "ok"
        assert hooks["data"]["hook_statuses"] == [
            {"hook": "fetch", "status": "installed"}
        ]
        assert hooks["data"]["requested_strategy"] == "preload"
        assert hooks["data"]["effective_strategy"] == "postload"
        assert hooks["data"]["plan"]["calls"][0]["tool"] == "browser_evaluate"

        invalid = json.loads(
            asyncio.run(
                mcp_server.hunter_browser_inject_hooks(
                    browser_session_id=session_id,
                    hooks=["fetch"],
                    strategy="invalid",
                    execute=True,
                )
            )
        )
        assert invalid["status"] == "error"

        results = json.loads(
            asyncio.run(
                mcp_server.hunter_browser_get_hook_results(
                    browser_session_id=session_id,
                    execute=True,
                )
            )
        )
        assert results["data"]["accepted"] == 1
        assert len(results["data"]["network_requests"]) == 1
    finally:
        mcp_server._set_browser_mcp_caller(None)
