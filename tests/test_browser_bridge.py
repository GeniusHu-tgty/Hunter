import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import mcp_server
from core.browser import (
    BrowserController,
    BrowserSessionStore,
    DynamicHookInjector,
    ElementLocator,
    WebSocketCapture,
)


BROWSER_TOOLS = {
    "hunter_browser_navigate",
    "hunter_browser_interact",
    "hunter_browser_capture_network",
    "hunter_browser_inject_hooks",
    "hunter_browser_get_hook_results",
    "hunter_browser_snapshot",
}


def test_navigate_and_wait_builds_playwright_mcp_sequence_with_failure_capture(tmp_path):
    controller = BrowserController(artifact_dir=tmp_path)

    plan = controller.navigate_and_wait(
        "https://example.test/app",
        {
            "selector": "#app-ready",
            "response_url": "**/api/bootstrap",
            "network_idle": True,
            "timeout_ms": 12000,
        },
    )

    assert plan["backend"] == "playwright-mcp"
    assert plan["operation"] == "navigate_and_wait"
    assert [call["tool"] for call in plan["calls"]] == [
        "browser_navigate",
        "browser_run_code",
        "browser_run_code",
        "browser_run_code",
        "browser_snapshot",
    ]
    assert plan["calls"][0]["arguments"]["url"] == "https://example.test/app"
    assert "waitForSelector" in plan["calls"][1]["arguments"]["code"]
    assert "waitForResponse" in plan["calls"][2]["arguments"]["code"]
    assert "waitForLoadState" in plan["calls"][3]["arguments"]["code"]
    assert {call["tool"] for call in plan["on_failure"]} == {
        "browser_take_screenshot",
        "browser_snapshot",
        "browser_console_messages",
    }


def test_interaction_operations_generate_snapshot_first_and_network_capture():
    controller = BrowserController()
    click = controller.click_and_capture(
        {"text": "Save", "role": "button"},
        capture_network=True,
    )
    form = controller.fill_form_and_submit(
        {
            "username": {"value": "researcher", "type": "text"},
            "remember": {"value": True, "type": "checkbox"},
            "role": {"value": "viewer", "type": "select"},
        },
        {"text": "Login", "role": "button"},
    )
    scroll = controller.scroll_and_load_more(3)

    assert click["calls"][0]["tool"] == "browser_snapshot"
    assert "browser_click" in [call["tool"] for call in click["calls"]]
    assert click["calls"][-1]["tool"] == "browser_network_requests"
    assert form["calls"][0]["tool"] == "browser_snapshot"
    assert any(call["tool"] == "browser_fill_form" for call in form["calls"])
    assert form["calls"][-1]["tool"] == "browser_click"
    assert scroll["calls"][0]["tool"] == "browser_run_code"
    assert scroll["calls"][0]["arguments"]["scroll_times"] == 3


def test_element_locator_returns_ordered_fallback_strategies_from_html():
    html = """
    <form id="login-form">
      <label for="user">Username</label>
      <input id="user" name="username" placeholder="Enter username">
      <input name="password" type="password">
      <button type="submit" aria-label="Login account">Login</button>
    </form>
    """
    locator = ElementLocator(html)

    login = locator.locate("Login", role="button")
    username = locator.locate("username")

    assert [item["strategy"] for item in login[:4]] == [
        "text",
        "aria-label",
        "context-submit",
        "css",
    ]
    assert any(item["strategy"] == "name" for item in username)
    assert any(item["strategy"] == "placeholder" for item in username)
    assert all("playwright" in item for item in login + username)


def test_locator_failure_plan_always_requests_screenshot_and_page_state():
    locator = ElementLocator("<div>No controls</div>")
    result = locator.locate_with_failure_plan("missing")

    assert result["status"] == "not-found"
    assert [call["tool"] for call in result["failure_calls"]] == [
        "browser_take_screenshot",
        "browser_snapshot",
        "browser_console_messages",
    ]


def test_hook_templates_exist_are_idempotent_and_parse_as_javascript():
    injector = DynamicHookInjector()
    validation = injector.validate_templates()

    assert set(validation) == {
        "xhr",
        "fetch",
        "crypto",
        "storage",
        "cookie",
        "websocket",
    }
    assert all(item["valid"] for item in validation.values())
    for item in validation.values():
        source = Path(item["path"]).read_text(encoding="utf-8")
        assert "__HUNTER_HOOK__" in source
        assert "__hunterHooks" in source
    websocket_source = Path(validation["websocket"]["path"]).read_text(encoding="utf-8")
    assert "__hunterWebSockets" in websocket_source

    node = shutil.which("node")
    if node:
        for item in validation.values():
            result = subprocess.run(
                [node, "--check", item["path"]],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr


def test_hook_injection_strategies_use_run_code_and_evaluate():
    injector = DynamicHookInjector()

    preload = injector.build_plan(["xhr", "fetch"], strategy="preload")
    postload = injector.build_plan(["crypto"], strategy="postload")
    refresh = injector.build_plan(
        ["storage", "cookie"],
        strategy="refresh",
        refresh_interval_ms=5000,
    )

    assert preload["calls"][0]["tool"] == "browser_run_code"
    assert "addInitScript" in preload["calls"][0]["arguments"]["code"]
    assert postload["calls"][0]["tool"] == "browser_evaluate"
    assert refresh["calls"][0]["tool"] == "browser_run_code"
    assert "setInterval" in refresh["calls"][0]["arguments"]["code"]


def test_websocket_capture_normalizes_json_binary_and_requires_independent_replay_approval():
    capture = WebSocketCapture()

    text = capture.normalize_message(
        direction="received",
        payload='{"type":"update","id":7}',
        timestamp=100.5,
    )
    binary = capture.normalize_message(
        direction="sent",
        payload=b"\x00\x00\x00\x05hello",
        timestamp=101.0,
    )
    blocked = capture.replay_plan(
        "wss://example.test/socket",
        {"type": "update", "id": 8},
        approved=False,
    )
    approved = capture.replay_plan(
        "wss://example.test/socket",
        {"type": "update", "id": 8},
        approved=True,
        allowed_origins=["https://example.test:443"],
    )

    assert text["message_type"] == "text"
    assert text["parsed"] == {"type": "update", "id": 7}
    assert binary["message_type"] == "binary"
    assert binary["format"]["length_prefix"] == 5
    assert blocked["status"] == "approval-required"
    assert approved["status"] == "approval-required"
    assert approved["reason"] == "independent-approval-required"
    assert "calls" not in approved


def test_websocket_diff_reports_structural_changes():
    diff = WebSocketCapture.compare(
        {"status": "ok", "items": [1, 2]},
        {"status": "ok", "items": [1, 2, 3], "admin": True},
    )

    assert diff["changed"] is True
    assert "$.admin" in diff["added_paths"]
    assert "$.items" in diff["changed_paths"]


def test_websocket_replay_requires_verifier_but_accepts_matching_trusted_token():
    capture = WebSocketCapture(
        approval_verifier=lambda token, context: {
            "approved": token == "trusted",
            "action": context["action"],
            "url": context["url"],
            "payload_sha256": context["payload_sha256"],
            "allowed_origins": [context["origin"]],
        }
    )

    plan = capture.replay_plan(
        "wss://example.test/socket",
        {"action": "ping"},
        approved=True,
        approval_token="trusted",
    )

    assert plan["status"] == "ready"
    assert plan["execution"] == "deferred"
    assert plan["calls"][0]["tool"] == "browser_evaluate"


def test_high_level_browser_operations_remain_deferred():
    controller = BrowserController()
    plans = [
        controller.intercept_websocket("**/socket"),
        controller.capture_network_traffic(1),
        controller.execute_in_context("() => document.title"),
        controller.auto_login("https://example.test/login", "user", "pass"),
        controller.auto_navigate_spa("https://example.test", "/admin"),
        controller.auto_trigger_api("https://example.test", "Load users"),
    ]

    assert all(plan["execution"] == "deferred" for plan in plans)
    assert all(plan["status"] == "proposed" for plan in plans)
    assert all(plan["backend"] == "playwright-mcp" for plan in plans)


def test_browser_observations_route_to_hunter_tool_descriptors():
    controller = BrowserController()
    routed = controller.route_observations(
        {
            "urls": [
                "https://example.test/app",
                "https://example.test/api/users",
            ],
            "api_endpoints": [
                {"url": "https://example.test/api/search?q=x", "method": "GET"},
                {"url": "https://example.test/api/login", "method": "POST"},
            ],
            "websockets": [{"url": "wss://example.test/socket"}],
            "forms": [
                {
                    "action": "https://example.test/search",
                    "method": "GET",
                    "fields": ["q"],
                }
            ],
        }
    )

    tools = [call["tool"] for call in routed["hunter_calls"]]
    assert "hunter_scan_plan" in tools
    assert "hunter_auto_websocket" in tools
    assert "hunter_auto_sqli" in tools
    assert "hunter_auto_xss" in tools
    assert "hunter_auto_csrf" in tools
    assert all(call["execution"] == "deferred" for call in routed["hunter_calls"])


def test_hook_result_store_parses_prefixed_console_messages(tmp_path):
    store = BrowserSessionStore(tmp_path)
    session = store.create("https://example.test")
    messages = [
        "normal log",
        '__HUNTER_HOOK__{"hook":"fetch","phase":"request","url":"/api"}',
        '__HUNTER_HOOK__{"hook":"websocket","direction":"received","data":"{\\"ok\\":true}"}',
    ]

    result = store.ingest_console(session["session_id"], messages)
    reopened = store.get(session["session_id"])

    assert result["accepted"] == 2
    assert len(reopened["hook_results"]) == 2
    assert reopened["hook_results"][0]["hook"] == "fetch"


def test_browser_mcp_tools_registered_contracted_and_smoke(tmp_path):
    registered = {
        name
        for name, value in vars(mcp_server).items()
        if name.startswith("hunter_") and callable(value)
    }
    assert BROWSER_TOOLS <= registered
    contract = json.loads(asyncio.run(mcp_server.hunter_contract_check()))
    assert BROWSER_TOOLS <= set(contract["data"]["required_tools"])
    assert contract["data"]["registered_tool_count"] >= 100

    mcp_server._reset_browser_store(tmp_path)
    navigate = json.loads(
        asyncio.run(
            mcp_server.hunter_browser_navigate(
                "https://example.test",
                wait_for={"network_idle": True},
            )
        )
    )
    assert navigate["status"] == "ok"
    session_id = navigate["data"]["browser_session_id"]

    hooks = json.loads(
        asyncio.run(
            mcp_server.hunter_browser_inject_hooks(
                browser_session_id=session_id,
                hooks=["xhr", "fetch"],
                strategy="preload",
            )
        )
    )
    assert hooks["status"] == "ok"
    assert hooks["data"]["plan"]["calls"][0]["tool"] == "browser_run_code"

    results = json.loads(
        asyncio.run(
            mcp_server.hunter_browser_get_hook_results(
                browser_session_id=session_id,
                console_messages=[
                    '__HUNTER_HOOK__{"hook":"xhr","phase":"request","url":"/api"}'
                ],
            )
        )
    )
    assert results["data"]["accepted"] == 1

    snapshot = json.loads(
        asyncio.run(
            mcp_server.hunter_browser_snapshot(
                browser_session_id=session_id,
                include_network=True,
            )
        )
    )
    assert snapshot["data"]["plan"]["operation"] == "snapshot"
