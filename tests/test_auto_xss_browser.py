import asyncio

import pytest

import core.auto_xss as auto_xss
from core.auto_xss import AutoXSS


class FakeBrowserController:
    def __init__(self, observation=None, error=None):
        self.execution_adapter = object()
        self.observation = observation or {}
        self.error = error
        self.plans = []

    def execute_plan(self, plan, execute=False):
        self.plans.append(plan)

        async def run():
            if self.error:
                return {
                    "status": "timeout",
                    "execution": "failed",
                    "error": self.error,
                }
            if plan["operation"] == "verify_xss":
                return {
                    "status": "ok",
                    "execution": "completed",
                    "execution_results": [
                        {
                            "tool": "browser_run_code",
                            "result": {"structuredContent": self.observation},
                        }
                    ],
                }
            return {
                "status": "ok",
                "execution": "completed",
                "execution_results": [
                    {
                        "tool": "browser_take_screenshot",
                        "result": {"path": "evidence/xss-likely.png"},
                    }
                ],
            }

        return run()


def browser_observation(**overrides):
    value = {
        "page_loaded": True,
        "alert_triggered": False,
        "payload_rendered": False,
        "dialogs": [],
        "html": "<html><body>clean</body></html>",
        "url": "https://example.test/search?q=x",
    }
    value.update(overrides)
    return value


def test_browser_verification_marks_alert_execution_verified(monkeypatch):
    payload = "<script>alert(1)</script>"
    controller = FakeBrowserController(
        browser_observation(
            alert_triggered=True,
            payload_rendered=True,
            dialogs=[{"type": "alert", "message": "1"}],
            html=f"<html><body>{payload}</body></html>",
        )
    )
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: controller)

    result = AutoXSS("https://example.test/search", param="q")._verify_payload_with_browser(
        payload,
        {"reflected": True, "encoded": {}},
    )

    assert result["verdict"] == "VERIFIED"
    assert result["alert_triggered"] is True
    assert result["browser_unavailable"] is False
    code = controller.plans[0]["calls"][0]["arguments"]["code"]
    assert "page.on('dialog'" in code
    assert "page.goto" in code


def test_browser_verification_marks_rendered_without_alert_likely_and_screenshots(monkeypatch):
    payload = "<script>alert(1)</script>"
    controller = FakeBrowserController(
        browser_observation(
            payload_rendered=True,
            html=f"<html><body>{payload}</body></html>",
        )
    )
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: controller)

    result = AutoXSS("https://example.test/search", param="q")._verify_payload_with_browser(
        payload,
        {"reflected": True, "encoded": {}},
    )

    assert result["verdict"] == "LIKELY"
    assert result["screenshot"] == "evidence/xss-likely.png"
    assert controller.plans[1]["calls"][0]["tool"] == "browser_take_screenshot"


def test_browser_verification_marks_missing_dom_payload_refuted(monkeypatch):
    controller = FakeBrowserController(browser_observation())
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: controller)

    result = AutoXSS("https://example.test/search", param="q")._verify_payload_with_browser(
        "<script>alert(1)</script>",
        {"reflected": True, "encoded": {}},
    )

    assert result["verdict"] == "REFUTED"
    assert result["page_loaded"] is True
    assert "screenshot" not in result


def test_browser_unavailable_falls_back_to_text_match(monkeypatch):
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: None)

    result = AutoXSS("https://example.test/search", param="q")._verify_payload_with_browser(
        "<script>alert(1)</script>",
        {"reflected": True, "encoded": {}},
    )

    assert result["verdict"] == "VERIFIED"
    assert result["browser_unavailable"] is True
    assert result["fallback"] == "text_match"


def test_browser_url_preserves_existing_query_and_replaces_injection_parameter():
    scanner = AutoXSS("https://example.test/search?lang=en&q=old", param="q")

    url = scanner._browser_payload_url("<script>alert(1)</script>")

    assert "lang=en" in url
    assert "q=old" not in url
    assert "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" in url


def test_auto_xss_impl_accepts_optional_browser_flag(monkeypatch):
    seen = {}

    def fake_run(self, **kwargs):
        seen.update(kwargs)
        return {"target": self.base_url, "vulnerable": False}

    monkeypatch.setattr(AutoXSS, "run_full_scan", fake_run)

    auto_xss.auto_xss_impl("https://example.test", verify_with_browser=True)

    assert seen["verify_with_browser"] is True


def test_mcp_auto_xss_forwards_browser_verification_and_preserves_browser_verdict(monkeypatch):
    import json
    import mcp_server

    captured = {}

    def fake_impl(base_url, **kwargs):
        captured.update(kwargs)
        return {
            "target": base_url,
            "vulnerable": False,
            "evidence": {
                "request": {},
                "response": {"body": "&lt;script&gt;alert(1)&lt;/script&gt;"},
                "baseline_response": {"body": "normal"},
                "payload": "<script>alert(1)</script>",
                "reproduction_count": 0,
                "metadata": {
                    "browser_verification": {
                        "verdict": "VERIFIED",
                        "alert_triggered": True,
                        "browser_unavailable": False,
                    }
                },
            },
        }

    async def caller(server_name, tool_name, arguments):
        return {"ok": True}

    monkeypatch.setattr(auto_xss, "auto_xss_impl", fake_impl)
    mcp_server._set_browser_mcp_caller(caller)
    try:
        result = json.loads(
            asyncio.run(
                mcp_server.hunter_auto_xss(
                    "https://example.test",
                    verify_with_browser=True,
                )
            )
        )
    finally:
        mcp_server._set_browser_mcp_caller(None)

    assert captured["verify_with_browser"] is True
    assert captured["browser_controller"].execution_adapter is not None
    assert result["verdict"]["verdict"] == "verified"
    assert result["vulnerable"] is True


@pytest.mark.parametrize(
    ("browser_verdict", "expected", "vulnerable"),
    [
        ("VERIFIED", "verified", True),
        ("LIKELY", "likely", False),
        ("INCONCLUSIVE", "inconclusive", False),
        ("REFUTED", "refuted", False),
    ],
)
def test_central_xss_verdict_honors_browser_execution_metadata(
    browser_verdict, expected, vulnerable
):
    import mcp_server

    result = mcp_server._assess_auto_result(
        "hunter_auto_xss",
        {
            "vulnerable": True,
            "evidence": {
                "request": {},
                "response": {"body": "<script>alert(1)</script>"},
                "baseline_response": {"body": "normal"},
                "payload": "<script>alert(1)</script>",
                "reproduction_count": 3,
                "metadata": {
                    "browser_verification": {
                        "verdict": browser_verdict,
                        "browser_unavailable": False,
                    }
                },
            },
        },
    )

    assert result["verdict"]["verdict"] == expected
    assert result["vulnerable"] is vulnerable


def test_browser_timeout_falls_back_to_existing_text_match(monkeypatch):
    controller = FakeBrowserController(error="browser timed out")
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: controller)

    result = AutoXSS("https://example.test/search", param="q")._verify_payload_with_browser(
        "<script>alert(1)</script>",
        {"reflected": True, "encoded": {}},
    )

    assert result["verdict"] == "VERIFIED"
    assert result["browser_unavailable"] is True
    assert "timed out" in result["error"]


def test_dom_xss_can_be_verified_when_http_response_does_not_reflect_payload():
    payload = "<script>alert(1)</script>"
    controller = FakeBrowserController(
        browser_observation(
            alert_triggered=True,
            payload_rendered=True,
            dialogs=[{"type": "alert", "message": "1"}],
            html=f"<html><body>{payload}</body></html>",
        )
    )
    scanner = AutoXSS(
        "https://example.test/search",
        param="q",
        browser_controller=controller,
    )
    scanner.baseline_response = {
        "status": 200,
        "headers": {},
        "body": "normal",
        "length": 6,
    }
    scanner.detect_context = lambda: "not_reflected"
    scanner.detect_dom_xss = lambda: {
        "vulnerable": True,
        "dom_sources": ["location.search"],
        "dom_sinks": [{"sink": "innerHTML", "severity": "high"}],
    }
    scanner._test_payload = lambda value: {
        "status": 200,
        "headers": {},
        "body": "clean response",
        "reflected": False,
        "encoded": {},
        "payload": value,
    }

    result = scanner.run_full_scan(verify_with_browser=True)

    assert result["vulnerable"] is True
    assert result["xss_type"] == "dom"
    assert result["browser_verification"]["verdict"] == "VERIFIED"
    assert result["evidence"]["metadata"]["browser_verification"]["alert_triggered"] is True


def test_http_prefilter_preserves_existing_query_parameters():
    seen = {}

    class Response:
        status_code = 200
        text = "clean"

    class Session:
        def get(self, url, **kwargs):
            seen["url"] = url
            return Response()

    scanner = AutoXSS(
        "https://example.test/search?lang=en&q=old",
        param="q",
        session=Session(),
    )
    scanner._test_payload("<script>alert(1)</script>")

    assert "lang=en" in seen["url"]
    assert "q=old" not in seen["url"]
    assert seen["url"].count("?") == 1


def test_browser_plan_compares_injected_alerts_against_baseline():
    scanner = AutoXSS("https://example.test/search", param="q")
    plan = scanner._browser_plan(
        "<script>alert(1)</script>",
        scanner._browser_payload_url("<script>alert(1)</script>"),
        scanner._browser_baseline_url(),
    )
    code = plan["calls"][0]["arguments"]["code"]

    assert "HUNTER_XSS_BASELINE_7392" in plan["baseline_url"]
    assert "const baseline = await collect(baselineUrl)" in code
    assert 'const expectedAlertMessage = "1"' in code
    assert "injectedAlerts > baselineAlerts" in code
    assert "document.createElement('template')" in code


def test_post_browser_verification_falls_back_without_testing_unrelated_get(monkeypatch):
    controller = FakeBrowserController(
        browser_observation(alert_triggered=True, payload_rendered=True)
    )
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: controller)
    scanner = AutoXSS("https://example.test/search", param="q", method="POST")

    result = scanner._verify_payload_with_browser(
        "<script>alert(1)</script>",
        {"reflected": True, "encoded": {}},
    )

    assert result["browser_unavailable"] is True
    assert result["fallback"] == "text_match"
    assert controller.plans == []


def test_dom_verification_still_runs_after_reflected_likely_candidate():
    payload = "<script>alert(1)</script>"

    class SequenceController(FakeBrowserController):
        def __init__(self):
            super().__init__()
            self.verify_count = 0

        def execute_plan(self, plan, execute=False):
            self.plans.append(plan)

            async def run():
                if plan["operation"] == "capture_xss_evidence":
                    return {
                        "status": "ok",
                        "execution": "completed",
                        "execution_results": [{"result": {"path": "evidence/likely.png"}}],
                    }
                self.verify_count += 1
                observation = browser_observation(
                    payload_rendered=True,
                    alert_triggered=self.verify_count == 2,
                    html=f"<html><body>{payload}</body></html>",
                )
                return {
                    "status": "ok",
                    "execution": "completed",
                    "execution_results": [{"result": observation}],
                }

            return run()

    controller = SequenceController()
    scanner = AutoXSS(
        "https://example.test/search",
        param="q",
        browser_controller=controller,
    )
    scanner.baseline_response = {
        "status": 200,
        "headers": {},
        "body": "normal",
        "length": 6,
    }
    scanner.detect_context = lambda: "html"
    scanner.detect_waf = lambda: False
    scanner.get_payloads_for_context = lambda context, waf: [payload]
    scanner.detect_dom_xss = lambda: {
        "vulnerable": True,
        "dom_sources": ["location.search"],
        "dom_sinks": [{"sink": "innerHTML", "severity": "high"}],
    }
    scanner._test_payload = lambda value: {
        "status": 200,
        "headers": {},
        "body": value,
        "reflected": True,
        "encoded": {},
        "payload": value,
    }

    result = scanner.run_full_scan(verify_with_browser=True)

    assert controller.verify_count == 2
    assert result["vulnerable"] is True
    assert result["xss_type"] == "dom"
    assert result["browser_verification"]["verdict"] == "VERIFIED"



def test_dynamic_alert_expression_uses_baseline_difference_without_literal_filter():
    scanner = AutoXSS("https://example.test/search", param="q")

    assert scanner._expected_alert_message("javascript:alert(document.cookie)") == ""
    assert scanner._expected_alert_message("<script>alert('owned')</script>") == "owned"


def test_screenshot_failure_downgrades_rendered_result_to_inconclusive(monkeypatch):
    payload = "<script>alert(1)</script>"

    class ScreenshotFailureController(FakeBrowserController):
        def execute_plan(self, plan, execute=False):
            self.plans.append(plan)

            async def run():
                if plan["operation"] == "capture_xss_evidence":
                    return {
                        "status": "timeout",
                        "execution": "failed",
                        "error": "screenshot timed out",
                    }
                return {
                    "status": "ok",
                    "execution": "completed",
                    "execution_results": [
                        {
                            "result": browser_observation(
                                payload_rendered=True,
                                html=f"<html><body>{payload}</body></html>",
                            )
                        }
                    ],
                }

            return run()

    controller = ScreenshotFailureController()
    monkeypatch.setattr(auto_xss, "_get_browser_controller", lambda: controller)

    result = AutoXSS("https://example.test/search", param="q")._verify_payload_with_browser(
        payload,
        {"reflected": True, "encoded": {}},
    )

    assert result["verdict"] == "INCONCLUSIVE"
    assert "screenshot timed out" in result["screenshot_error"]
    assert "screenshot" not in result
