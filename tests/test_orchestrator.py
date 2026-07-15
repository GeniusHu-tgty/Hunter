import asyncio
import hashlib
import inspect
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import core.memory
import core.unified_scanner
import mcp_server
import pytest

from core.workflow.kernel import (
    OrchestratorInterrupted,
    UnifiedOrchestrator,
    WorkflowKernel,
)


STAGES = (
    "memory",
    "recon",
    "attack_surface",
    "attack_execution",
    "vulnerability_confirmation",
    "evidence_learning",
    "report",
)


def _workflow(kernel, slug="orchestrator-case", mode="autopilot"):
    kernel.create(
        slug,
        "authorized unified orchestration test",
        inputs=[{"type": "url", "value": "https://example.test"}],
        mode=mode,
        success_conditions=["confirmed-finding"],
        proof_types=["request-response"],
    )
    return slug


def _adapters(calls, pause_once=False):
    paused = {"value": False}

    def adapter(stage, result):
        def run(context):
            calls.append(stage)
            if pause_once and stage == "attack_execution" and not paused["value"]:
                paused["value"] = True
                raise OrchestratorInterrupted("test interruption")
            return result

        return run

    return {
        "memory": adapter(
            "memory",
            {
                "memo": {
                    "target_seen": True,
                    "best_techniques": ["case-variation"],
                    "fingerprints": {"waf": "Cloudflare"},
                }
            },
        ),
        "recon": adapter(
            "recon",
            {
                "target_profile": {
                    "target_url": "https://example.test",
                    "fingerprints": {"waf": "Cloudflare", "framework": "Django"},
                    "api_endpoints": ["/api/search"],
                }
            },
        ),
        "attack_surface": adapter(
            "attack_surface",
            {"attack_queue": [{"kind": "sqli", "target": "/api/search"}]},
        ),
        "attack_execution": adapter(
            "attack_execution",
            {
                "attempts": [{"technique": "case-variation", "success": True}],
                "handoffs": [{"execution": "deferred", "tool": "hunter_auto_sqli"}],
            },
        ),
        "vulnerability_confirmation": adapter(
            "vulnerability_confirmation",
            {
                "findings": [
                    {
                        "title": "SQL injection",
                        "status": "confirmed",
                        "severity": "high",
                        "satisfies": ["confirmed-finding"],
                    }
                ]
            },
        ),
        "evidence_learning": adapter(
            "evidence_learning",
            {
                "evidence": [{"summary": "request-response pair"}],
                "learning_updates": [{"technique": "case-variation", "success": True}],
            },
        ),
        "report": adapter(
            "report",
            {"report_path": "reports/orchestrator-case.md"},
        ),
    }


def test_unified_orchestrator_runs_all_stages_and_persists_progress(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    calls = []
    orchestrator = UnifiedOrchestrator(kernel, adapters=_adapters(calls))

    result = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["all"],
        policy="standard",
    )

    assert result["status"] == "completed"
    assert calls == list(STAGES)
    assert set(result["stage_results"]) == set(STAGES)
    assert result["memo"]["fingerprints"]["waf"] == "Cloudflare"
    assert result["target_profile"]["api_endpoints"] == ["/api/search"]
    assert result["attack_queue"][0]["kind"] == "sqli"
    assert result["findings"][0]["severity"] == "high"
    assert result["report_path"].endswith("reports/orchestrator-case.md")
    assert result["checkpoints_created"] == len(STAGES)

    state = kernel.materialize(slug)
    assert state["orchestrator"]["current_stage"] == "complete"
    assert state["orchestrator"]["stage_status"]["report"] == "completed"
    assert state["metrics"]["checkpoints"] >= len(STAGES)
    assert len(state["evidence"]) == 1
    assert state["findings"][0]["title"] == "SQL injection"
    status = kernel.status(slug)
    assert status["orchestrator"]["status"] == "completed"
    assert status["stage_results"]["report"]["report_path"].endswith(
        "reports/orchestrator-case.md"
    )


def test_orchestrator_interruption_creates_checkpoint_and_resume_continues(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    calls = []
    adapters = _adapters(calls, pause_once=True)
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    interrupted = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["web"],
        policy="standard",
    )

    assert interrupted["status"] == "interrupted"
    assert interrupted["interrupted_stage"] == "attack_execution"
    assert interrupted["checkpoint_id"]
    assert calls == list(STAGES[:3]) + ["attack_execution"]

    resumed = orchestrator.resume(slug, target_url="https://example.test")

    assert resumed["status"] == "completed"
    assert resumed["resumed_from"] == "attack_execution"
    assert calls == list(STAGES[:3]) + ["attack_execution"] + list(STAGES[3:])


def test_concurrent_orchestrators_execute_each_stage_once(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    calls = []
    adapters = _adapters(calls)

    for stage, adapter in list(adapters.items()):
        def slow_adapter(context, _adapter=adapter):
            time.sleep(0.02)
            return _adapter(context)

        adapters[stage] = slow_adapter

    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    def run():
        return orchestrator.orchestrate(
            slug,
            target_url="https://example.test",
            modules=["web"],
            policy="standard",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run), pool.submit(run)]
        results = [future.result() for future in futures]

    assert all(result["status"] == "completed" for result in results)
    assert calls == list(STAGES)


def test_interactive_policy_pauses_before_high_impact_actions(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")

    adapters = _adapters([])
    original = adapters["attack_execution"]
    adapters["attack_execution"] = lambda context: {
        "confirmation_required": True,
        "reason": "confirmed command execution requires analyst approval",
        "actions": [{"tool": "hunter_post_exploit", "execution": "deferred"}],
    }
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    result = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["web"],
        policy="standard",
    )

    assert result["status"] == "awaiting_confirmation"
    assert result["confirmation_required"][0]["tool"] == "hunter_post_exploit"
    assert result["current_stage"] == "attack_execution"
    assert original is not None
    pending = result["confirmation_required"][0]

    approved = orchestrator.resume(
        slug,
        target_url="https://example.test",
        approval={
            "stage": "attack_execution",
            "approved": True,
            "decision_id": "decision-001",
            "confirmation_id": pending["confirmation_id"],
            "confirmation_digest": pending["confirmation_digest"],
            "scope": pending["scope"],
        },
    )
    assert approved["status"] == "completed"


def _confirmation_adapters(marker_default="A"):
    adapters = _adapters([])

    def attack_execution(context):
        marker = context.get("observations", {}).get(
            "marker", marker_default
        )
        return {
            "confirmation_required": [
                {
                    "tool": "hunter_post_exploit",
                    "execution": "deferred",
                    "arguments": {"finding": marker},
                    "scope": {"finding": marker},
                }
            ],
            "reason": "analyst approval required",
        }

    adapters["attack_execution"] = attack_execution
    return adapters


def test_approval_requires_an_existing_pending_confirmation(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )

    with pytest.raises(ValueError, match="pending confirmation"):
        orchestrator.orchestrate(
            slug,
            target_url="https://example.test",
            approval={
                "stage": "attack_execution",
                "approved": True,
                "decision_id": "premature",
                "confirmation_id": "confirm-missing",
                "confirmation_digest": "0" * 64,
                "scope": {"finding": "A"},
            },
        )


def test_approval_for_action_a_does_not_authorize_changed_action_b(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )
    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )
    pending = first["confirmation_required"][0]

    changed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        observations={"marker": "B"},
        approval={
            "stage": "attack_execution",
            "approved": True,
            "decision_id": "approve-a",
            "confirmation_id": pending["confirmation_id"],
            "confirmation_digest": pending["confirmation_digest"],
            "scope": pending["scope"],
        },
    )

    assert changed["status"] == "awaiting_confirmation"
    assert changed["confirmation_required"][0]["arguments"]["finding"] == "B"


def test_approval_scope_must_match_pending_confirmation(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )
    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )
    pending = first["confirmation_required"][0]

    with pytest.raises(ValueError, match="scope"):
        orchestrator.resume(
            slug,
            target_url="https://example.test",
            approval={
                "stage": "attack_execution",
                "approved": True,
                "decision_id": "bad-scope",
                "confirmation_id": pending["confirmation_id"],
                "confirmation_digest": pending["confirmation_digest"],
                "scope": {"finding": "B"},
            },
        )


def test_exact_approval_is_consumed_after_stage_completion(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="interactive")
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_confirmation_adapters()
    )
    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )
    pending = first["confirmation_required"][0]

    completed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        approval={
            "stage": "attack_execution",
            "approved": True,
            "decision_id": "exact-approval",
            "confirmation_id": pending["confirmation_id"],
            "confirmation_digest": pending["confirmation_digest"],
            "scope": pending["scope"],
        },
    )

    assert completed["status"] == "completed"
    approval = kernel.materialize(slug)["orchestrator"]["approvals"][0]
    assert approval["consumed"] is True
    assert approval["consumed_at"]


def test_default_high_impact_confirmation_is_required_in_autopilot(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel, mode="autopilot")
    orchestrator = UnifiedOrchestrator(kernel)
    state = kernel.materialize(slug)
    context = orchestrator._context(
        state,
        "https://example.test",
        ["web"],
        orchestrator._profile("standard"),
    )
    context["stage_results"]["attack_execution"] = {
        "attempts": [
            {
                "action_id": "act-rce",
                "tool": "hunter_auto_cmd",
                "attack_surface": "rce",
                "target": "https://example.test/exec",
                "response": {
                    "data": {
                        "evidence": {
                            "request": {
                                "url": "https://example.test/exec",
                            },
                            "response": {
                                "status_code": 200,
                                "body": (
                                    "uid=1000(www-data) "
                                    "gid=1000(www-data)"
                                ),
                            },
                            "baseline_response": {
                                "status_code": 200,
                                "body": "normal",
                            },
                            "payload": "id",
                            "reproduction_count": 3,
                        }
                    }
                },
            }
        ]
    }

    result = orchestrator._stage_confirmation(context)

    assert result["confirmation_required"]
    assert result["confirmation_required"][0]["tool"] == "hunter_post_exploit"


def test_default_recon_uses_stealth_scan_for_spa_and_websocket_analysis(
    tmp_path,
):
    class FakeStealthClient:
        def __init__(self):
            self.scan_calls = []
            self.request_calls = []

        def stealth_scan(self, target, options=None):
            self.scan_calls.append((target, options or {}))
            return {
                "target": target,
                "baseline": {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {"Server": "cloudflare"},
                    "body": (
                        '<div id="root"></div>'
                        '<script src="/assets/app.js"></script>'
                    ),
                    "timeline": [],
                },
                "waf": {
                    "waf_type": "Cloudflare",
                    "blocked_probes": 1,
                    "probes": [],
                },
                "rate_limit": {"tested_rates": [1, 2]},
                "captcha": {"type": None},
                "session": {"session_id": "stealth-test"},
            }

        def stealth_request(
            self,
            method,
            url,
            headers=None,
            data=None,
            options=None,
        ):
            self.request_calls.append((method, url, options or {}))
            return {
                "status": "ok",
                "status_code": 200,
                "headers": {"Content-Type": "application/javascript"},
                "body": (
                    "function __webpack_require__(id){return id;}"
                    "const socket = new WebSocket('wss://example.test/ws');"
                    + ("x" * 70000)
                ),
                "timeline": [],
            }

    class FakeBrowserController:
        def __init__(self):
            self.patterns = []

        def intercept_websocket(self, url_pattern="*"):
            self.patterns.append(url_pattern)
            return {
                "operation": "intercept_websocket",
                "execution": "deferred",
                "url_pattern": url_pattern,
            }

    stealth = FakeStealthClient()
    browser = FakeBrowserController()
    js_calls = []

    def js_full_analysis(sources, **kwargs):
        js_calls.append((sources, kwargs))
        return {
            "api": {
                "endpoints": [
                    {
                        "url": "/api/users",
                        "method": "POST",
                        "parameters": ["user_id"],
                    }
                ],
                "websockets": [
                    {
                        "url": "wss://example.test/ws",
                        "message_formats": [
                            {"kind": "json", "fields": ["type", "token"]}
                        ],
                    }
                ],
            },
            "signature": {"replay_status": "signing-scaffold"},
        }

    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel,
        services={
            "stealth_http_client": stealth,
            "browser_controller": browser,
            "js_full_analysis": js_full_analysis,
        },
    )
    context = orchestrator._context(
        kernel.materialize(slug),
        "https://example.test",
        ["all"],
        orchestrator._profile("standard"),
    )

    result = orchestrator._stage_recon(context)
    profile = result["target_profile"]

    assert stealth.scan_calls
    assert stealth.scan_calls[0][0] == "https://example.test"
    assert len(stealth.request_calls) == 1
    assert stealth.request_calls[0][:2] == (
        "GET",
        "https://example.test/assets/app.js",
    )
    assert js_calls
    assert browser.patterns == ["wss://example.test/ws"]
    assert profile["fingerprints"]["waf"] == "Cloudflare"
    assert profile["stealth_required"] is True
    assert profile["http_transport"] == "stealth_http_client"
    assert profile["spa"]["detected"] is True
    assert profile["js_analysis"]["triggered"] is True
    assert profile["api_endpoints"][0]["url"] == "/api/users"
    assert profile["websocket_capture"]["triggered"] is True


def test_recon_executes_spa_websocket_and_hook_operations_with_mcp_callback():
    class FakeStealthClient:
        def stealth_scan(self, target, options=None):
            return {
                "target": target,
                "baseline": {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {},
                    "body": (
                        '<div id="root"></div>'
                        '<a href="/dashboard">Dashboard</a>'
                        "<script>window.__webpack_require__ = function(){};</script>"
                    ),
                    "timeline": [],
                },
                "waf": {},
                "rate_limit": {},
                "captcha": {},
            }

        def stealth_request(self, *args, **kwargs):
            raise AssertionError("inline SPA should not fetch external scripts")

    class FakeFingerprintDatabase:
        @staticmethod
        def detect(observation):
            return {}

    calls = []

    async def caller(backend_name, tool_name, arguments):
        calls.append((backend_name, tool_name, arguments))
        if tool_name == "browser_evaluate":
            function = str(arguments.get("function") or "")
            if "html_length" in function:
                return {
                    "value": {
                        "url": "https://example.test/dashboard",
                        "title": "Dashboard",
                        "html_length": 2048,
                        "has_form": True,
                        "has_login": False,
                        "has_websocket": True,
                    }
                }
            return {
                "value": {
                    "installed": True,
                    "url": "https://example.test/dashboard",
                }
            }
        if tool_name == "browser_console_logs":
            return {
                "logs": [
                    '__HUNTER_HOOK__{"hook":"fetch","url":"/api/users"}',
                    '__HUNTER_HOOK__{"hook":"websocket","direction":"received","data":"ok"}',
                ]
            }
        return {"ok": True}

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "stealth_http_client": FakeStealthClient(),
            "fingerprint_database": FakeFingerprintDatabase(),
            "js_full_analysis": lambda sources, **kwargs: {
                "api": {
                    "endpoints": [
                        {
                            "url": "/dashboard",
                            "method": "GET",
                            "parameters": [],
                        }
                    ],
                    "websockets": [{"url": "wss://example.test/ws"}],
                }
            },
        },
        call_mcp_tool=caller,
        js_threshold=1,
    )

    result = bridge.stage_recon(
        {
            "target_url": "https://example.test",
            "profile": {
                "name": "standard",
                "max_endpoints": 10,
                "max_attack_surfaces": 5,
            },
            "workflow_id": "browser-execution",
        }
    )
    profile = result["target_profile"]

    assert {item[0] for item in calls} == {"playwright-mcp"}
    assert "browser_navigate" in [item[1] for item in calls]
    assert "browser_run_code" in [item[1] for item in calls]
    assert "browser_evaluate" in [item[1] for item in calls]
    assert "browser_console_logs" in [item[1] for item in calls]
    assert profile["browser_analysis"]["execution"] == "completed"
    assert profile["browser_analysis"]["navigation"]["status"] == "ok"
    assert profile["browser_analysis"]["spa_routes"][0]["status"] == "ok"
    assert profile["browser_analysis"]["hook_injection"]["status"] == "ok"
    assert len(
        profile["browser_analysis"]["hook_results"]["network_requests"]
    ) == 1
    assert len(
        profile["browser_analysis"]["hook_results"]["websocket_messages"]
    ) == 1
    assert profile["websocket_capture"]["plans"][0]["status"] == "ok"
    assert profile["browser_evidence"] == []


def test_browser_result_summary_rejects_failed_installation_and_redacts_hooks():
    bridge = core.unified_scanner.UnifiedOrchestrationBridge()
    summary = bridge._browser_result_summary(
        "intercept_websocket",
        {
            "status": "ok",
            "execution": "completed",
            "execution_results": [
                {
                    "tool": "browser_run_code",
                    "result": {
                        "value": {
                            "installed": False,
                            "pattern": "wss://example.test/ws",
                        }
                    },
                }
            ],
            "hook_results": [
                {
                    "hook": "websocket",
                    "data": '{"token":"super-secret"}',
                }
            ],
            "websocket_messages": [
                {
                    "hook": "websocket",
                    "data": '{"password":"also-secret"}',
                }
            ],
        },
    )

    serialized = json.dumps(summary)
    assert summary["status"] == "error"
    assert summary["installed"] is False
    assert summary["pattern"] == "wss://example.test/ws"
    assert "super-secret" not in serialized
    assert "also-secret" not in serialized
    assert "[REDACTED]" in serialized


def test_browser_failures_become_evidence_without_blocking_recon():
    class FakeStealthClient:
        def stealth_scan(self, target, options=None):
            return {
                "target": target,
                "baseline": {
                    "status": "ok",
                    "status_code": 200,
                    "headers": {},
                    "body": '<div id="root"></div>',
                    "timeline": [],
                },
                "waf": {},
                "rate_limit": {},
                "captcha": {},
            }

    class FakeFingerprintDatabase:
        @staticmethod
        def detect(observation):
            return {}

    class FakeTargetMemory:
        @staticmethod
        def query_target(target):
            return {"fingerprints": {}}

        @staticmethod
        def record_target(*args, **kwargs):
            return {}

    class FakeTechniqueMemory:
        pass

    async def offline_caller(backend_name, tool_name, arguments):
        raise RuntimeError("Playwright backend is offline")

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "stealth_http_client": FakeStealthClient(),
            "fingerprint_database": FakeFingerprintDatabase(),
            "target_memory": FakeTargetMemory(),
            "technique_memory": FakeTechniqueMemory(),
        },
        call_mcp_tool=offline_caller,
        js_threshold=1,
    )
    recon = bridge.stage_recon(
        {
            "target_url": "https://example.test",
            "profile": {
                "name": "standard",
                "max_endpoints": 10,
                "max_attack_surfaces": 5,
            },
            "workflow_id": "browser-failure",
        }
    )
    profile = recon["target_profile"]

    assert profile["http_status"] == 200
    assert profile["spa"]["detected"] is True
    assert profile["browser_analysis"]["execution"] == "failed"
    assert profile["browser_evidence"]
    assert "Playwright backend is offline" in profile["browser_evidence"][0][
        "summary"
    ]

    evidence_result = bridge.stage_evidence_learning(
        {
            "target_url": "https://example.test",
            "target_profile": profile,
            "stage_results": {
                "recon": recon,
                "attack_execution": {"attempts": [], "handoffs": []},
                "vulnerability_confirmation": {"findings": []},
            },
        }
    )

    assert evidence_result["evidence"][0]["type"] == "browser_error"
    assert evidence_result["evidence"][0]["source"] == "browser-controller"


def test_recon_records_adaptive_stealth_strategy_outcomes(tmp_path):
    class FakeStealthClient:
        def __init__(self):
            self.results = [
                {
                    "status": "blocked",
                    "status_code": 403,
                    "headers": {},
                    "body": "Access denied by policy",
                    "timeline": [
                        {
                            "attempt": 1,
                            "strategy": "parameter-order",
                            "strategy_status": "applied",
                            "status_code": 403,
                            "rate_limited": False,
                            "waf": {"blocked": True, "block_keyword": True},
                        },
                        {
                            "attempt": 2,
                            "strategy": "not-implemented",
                            "strategy_status": "unsupported",
                            "status_code": 403,
                            "rate_limited": False,
                            "waf": {"blocked": False, "block_keyword": False},
                        },
                    ],
                },
                {
                    "status": "blocked",
                    "status_code": 500,
                    "headers": {},
                    "body": "Internal server error",
                    "timeline": [
                        {
                            "attempt": 1,
                            "strategy": "content-type-rotation",
                            "strategy_status": "applied",
                            "status_code": 500,
                            "rate_limited": False,
                            "waf": {"blocked": False, "block_keyword": False},
                        },
                        {
                            "attempt": 2,
                            "strategy": "chunked-body",
                            "strategy_status": "applied",
                            "status_code": 503,
                            "rate_limited": True,
                            "waf": {"blocked": False, "block_keyword": False},
                        },
                    ],
                },
            ]

        def stealth_scan(self, target, options=None):
            return {
                "target": target,
                "baseline": {
                    "status": "ok",
                    "status_code": 301,
                    "headers": {},
                    "body": (
                        '<script src="/assets/one.js"></script>'
                        '<script src="/assets/two.js"></script>'
                    ),
                    "timeline": [
                        {
                            "attempt": 1,
                            "strategy": "header-consistency",
                            "strategy_status": "applied",
                            "status_code": 301,
                            "rate_limited": False,
                            "waf": {"blocked": False, "block_keyword": False},
                        }
                    ],
                },
                "waf": {
                    "waf_type": "Alibaba Cloud WAF",
                    "blocked_probes": 1,
                    "probes": [],
                },
                "rate_limit": {},
                "captcha": {"type": None},
            }

        def stealth_request(
            self,
            method,
            url,
            headers=None,
            data=None,
            options=None,
        ):
            return self.results.pop(0)

    class FakeTechniqueMemory:
        def __init__(self):
            self.attempts = []

        def record_attempt(self, **kwargs):
            self.attempts.append(kwargs)
            return kwargs

    memory = FakeTechniqueMemory()
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel,
        services={
            "stealth_http_client": FakeStealthClient(),
            "technique_memory": memory,
        },
    )
    context = orchestrator._context(
        kernel.materialize(slug),
        "https://example.test",
        ["all"],
        orchestrator._profile("standard"),
    )

    orchestrator._stage_recon(context)

    assert [
        (item["technique_name"], item["success"])
        for item in memory.attempts
    ] == [
        ("header-consistency", True),
        ("parameter-order", False),
        ("content-type-rotation", True),
    ]
    assert {item["waf_type"] for item in memory.attempts} == {
        "Alibaba Cloud WAF"
    }
    assert [item["target_url"] for item in memory.attempts] == [
        "https://example.test",
        "https://example.test/assets/one.js",
        "https://example.test/assets/two.js",
    ]


def test_recon_strategy_learning_is_idempotent_per_workflow():
    class FakeTechniqueMemory:
        def __init__(self):
            self.records = []

        def attempts(self, technique_name=None, target_url=None, limit=100):
            return [
                item
                for item in reversed(self.records)
                if (
                    not technique_name
                    or item["technique_name"] == technique_name
                )
                and (not target_url or item["target_url"] == target_url)
            ][:limit]

        def record_attempt(self, **kwargs):
            self.records.append(kwargs)
            return kwargs

    memory = FakeTechniqueMemory()
    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {"technique_memory": memory}
    )
    result = {
        "status": "ok",
        "status_code": 200,
        "body": "normal page",
        "timeline": [
            {
                "attempt": 1,
                "strategy": "case-variation",
                "strategy_status": "applied",
                "status_code": 200,
                "rate_limited": False,
                "waf": {"blocked": False, "block_keyword": False},
            }
        ],
    }

    bridge._record_stealth_strategy_attempts(
        result,
        target_url="https://example.test/api",
        waf_type="Cloudflare",
        learning_run_id="workflow-1",
    )
    bridge._record_stealth_strategy_attempts(
        {
            **result,
            "status_code": 403,
            "body": "Access denied",
            "timeline": [
                {
                    **result["timeline"][0],
                    "status_code": 403,
                    "waf": {"blocked": True, "block_keyword": True},
                }
            ],
        },
        target_url="https://example.test/api",
        waf_type="Cloudflare",
        learning_run_id="workflow-1",
    )
    bridge._record_stealth_strategy_attempts(
        result,
        target_url="https://example.test/api",
        waf_type="Cloudflare",
        learning_run_id="workflow-1",
    )
    bridge._record_stealth_strategy_attempts(
        result,
        target_url="https://example.test/api",
        waf_type="Cloudflare",
        learning_run_id="workflow-2",
    )

    assert len(memory.records) == 2
    assert {
        item["metadata"]["learning_run_id"] for item in memory.records
    } == {"workflow-1", "workflow-2"}


def test_recon_does_not_apply_final_body_to_earlier_timeline_rows():
    class FakeTechniqueMemory:
        def __init__(self):
            self.records = []

        def record_attempt(self, **kwargs):
            self.records.append(kwargs)
            return kwargs

    memory = FakeTechniqueMemory()
    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {"technique_memory": memory}
    )

    bridge._record_stealth_strategy_attempts(
        {
            "body": "Access denied appears in the final application page",
            "timeline": [
                {
                    "attempt": 1,
                    "strategy": "parameter-order",
                    "strategy_status": "applied",
                    "status_code": 403,
                    "rate_limited": False,
                    "waf": {"blocked": False, "block_keyword": False},
                },
                {
                    "attempt": 2,
                    "strategy": "case-variation",
                    "strategy_status": "applied",
                    "status_code": 200,
                    "rate_limited": False,
                    "waf": {"blocked": False, "block_keyword": False},
                },
            ],
        },
        target_url="https://example.test/api",
        waf_type="Cloudflare",
        learning_run_id="workflow-1",
    )

    assert [
        (item["technique_name"], item["success"])
        for item in memory.records
    ] == [("case-variation", True)]


def test_attack_execution_queries_patterns_and_memory_before_probe(tmp_path):
    class FakePatternEngine:
        def __init__(self):
            self.parameters = []

        def match_parameter(self, parameter, context=""):
            self.parameters.append((parameter, context))
            return {
                "parameter": parameter,
                "vulnerability_types": ["sqli", "xss"],
                "confidence": 0.95,
                "evidence": [{"type": "parameter-name"}],
            }

    class FakeTechniqueMemory:
        def best_for_waf(self, waf_type, limit=10, include_retired=False):
            return [
                {
                    "name": "case-variation",
                    "success_rate": 0.9,
                    "waf_type": waf_type,
                }
            ]

    pattern_engine = FakePatternEngine()
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel,
        services={
            "pattern_engine": pattern_engine,
            "technique_memory": FakeTechniqueMemory(),
        },
    )
    context = orchestrator._context(
        kernel.materialize(slug),
        "https://example.test",
        ["web"],
        orchestrator._profile("standard"),
    )
    context["target_profile"] = {
        "fingerprints": {"waf": "Cloudflare", "framework": "React"}
    }
    context["attack_queue"] = [
        {
            "kind": "sqli_xss",
            "target": "https://example.test/api/search",
            "parameters": ["query"],
        }
    ]

    result = orchestrator._stage_attack_execution(context)
    probe = next(
        item
        for item in result["handoffs"]
        if item.get("tool") == "hunter_auto_sqli"
    )

    assert pattern_engine.parameters == [
        ("query", "https://example.test/api/search")
    ]
    assert probe["http_transport"] == "stealth_http_client"
    assert probe["preflight"]["parameter_patterns"][0][
        "vulnerability_types"
    ] == ["sqli", "xss"]
    assert probe["preflight"]["recommended_techniques"][0][
        "name"
    ] == "case-variation"


def test_attack_execution_opens_dynamic_form_surfaces_with_browser_callback():
    class FakePatternEngine:
        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class FakeTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class FakeTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    calls = []

    async def caller(backend_name, tool_name, arguments):
        calls.append((backend_name, tool_name, arguments))
        if tool_name == "browser_evaluate":
            return {
                "value": {
                    "url": "https://example.test/login",
                    "title": "Login",
                    "html_length": 1024,
                    "has_form": True,
                    "has_login": True,
                    "has_websocket": False,
                }
            }
        return {"ok": True}

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": FakeTechniqueMemory(),
            "target_memory": FakeTargetMemory(),
        },
        call_mcp_tool=caller,
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "authentication",
                    "target": "https://example.test/login",
                    "method": "GET",
                    "parameters": ["username", "password"],
                }
            ],
        }
    )

    assert result["browser_operations"][0]["status"] == "ok"
    assert result["browser_operations"][0]["has_login"] is True
    assert result["browser_evidence"] == []
    assert "browser_navigate" in [item[1] for item in calls]
    assert not any(
        handoff.get("tool") == "hunter_browser_navigate"
        for handoff in result["handoffs"]
    )


def test_dynamic_form_browser_failure_keeps_deferred_navigation_fallback():
    class FakePatternEngine:
        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class FakeTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class FakeTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    async def offline_caller(backend_name, tool_name, arguments):
        raise RuntimeError("Playwright backend is offline")

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": FakeTechniqueMemory(),
            "target_memory": FakeTargetMemory(),
        },
        call_mcp_tool=offline_caller,
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "authentication",
                    "target": "https://example.test/login",
                    "method": "GET",
                    "parameters": [],
                }
            ],
        }
    )

    assert result["browser_operations"][0]["status"] == "error"
    assert result["browser_evidence"][0]["type"] == "browser_error"
    assert any(
        handoff.get("tool") == "hunter_browser_navigate"
        for handoff in result["handoffs"]
    )


def test_confirmation_requires_normalized_proof_and_flags_false_positives(
    tmp_path,
):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(kernel)
    context = orchestrator._context(
        kernel.materialize(slug),
        "https://example.test",
        ["web"],
        orchestrator._profile("standard"),
    )
    context["stage_results"]["attack_execution"] = {
        "attempts": [
            {
                "action_id": "act-sqli",
                "tool": "hunter_auto_sqli",
                "attack_surface": "sqli",
                "target": "https://example.test/?id=1",
                "session_id": "session-sqli",
                "response": {
                    "data": {
                        "evidence": {
                            "request": {
                                "url": "https://example.test/?id=1'",
                            },
                            "response": {
                                "status_code": 500,
                                "body": (
                                    "You have an error in your SQL syntax"
                                ),
                            },
                            "baseline_response": {
                                "status_code": 200,
                                "body": "normal application response",
                            },
                            "payload": "'",
                            "reproduction_count": 3,
                        }
                    }
                },
            }
        ]
    }
    context["observations"] = {
        "responses": [
            {
                "body": "normal application response",
                "vulnerability_type": "xss",
                "vulnerable": True,
                "session_id": "session-xss",
            },
        ]
    }

    result = orchestrator._stage_confirmation(context)

    assert [item["type"] for item in result["findings"]] == ["sqli"]
    assert result["false_positives"][0]["type"] == "xss"
    assert result["false_positives"][0]["status"] == "probable_false_positive"
    assert result["post_exploitation_handoffs"][0]["arguments"][
        "vuln_details"
    ]["verification_depth"] == "deep"
    assert result["post_exploitation_handoffs"][0]["arguments"][
        "session_id"
    ] == "session-sqli"


def test_evidence_learning_persists_stack_attempts_and_confirmed_findings(
    tmp_path,
    monkeypatch,
):
    class FakeTargetMemory:
        def __init__(self):
            self.targets = []
            self.fingerprints = []
            self.endpoints = []
            self.attacks = []
            self.vulnerabilities = []

        def record_target(
            self,
            target_url,
            fingerprints=None,
            technology_stack=None,
        ):
            self.targets.append(
                (target_url, fingerprints or {}, technology_stack or {})
            )
            return {"url": target_url}

        def record_fingerprint(self, target_url, fingerprints, *args, **kwargs):
            self.fingerprints.append((target_url, fingerprints))
            return {"target_url": target_url}

        def record_endpoint(self, target_url, endpoint_url, **kwargs):
            self.endpoints.append((target_url, endpoint_url, kwargs))
            return {"url": endpoint_url}

        def record_attack(self, target_url, **kwargs):
            self.attacks.append((target_url, kwargs))
            return kwargs

        def record_vulnerability(self, target_url, **kwargs):
            self.vulnerabilities.append((target_url, kwargs))
            return kwargs

    class FakeTechniqueMemory:
        def __init__(self):
            self.attempts = []

        def record_attempt(self, **kwargs):
            self.attempts.append(kwargs)
            return kwargs

    target_memory = FakeTargetMemory()
    technique_memory = FakeTechniqueMemory()
    monkeypatch.setattr(
        core.memory,
        "TargetMemory",
        lambda: target_memory,
    )
    monkeypatch.setattr(
        core.memory,
        "TechniqueMemory",
        lambda: technique_memory,
    )

    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel,
        services={
            "target_memory": target_memory,
            "technique_memory": technique_memory,
        },
    )
    context = orchestrator._context(
        kernel.materialize(slug),
        "https://example.test",
        ["web"],
        orchestrator._profile("standard"),
    )
    context["target_profile"] = {
        "fingerprints": {
            "waf": "Cloudflare",
            "framework": "React",
            "server": "nginx",
        },
        "api_endpoints": [
            {
                "url": "https://example.test/api/users",
                "method": "POST",
                "parameters": ["user_id"],
            }
        ],
    }
    context["stage_results"] = {
        "attack_execution": {
            "attempts": [
                {
                    "technique": "case-variation",
                    "success": True,
                    "target": "https://example.test/api/users",
                },
                {
                    "technique": "plain-payload",
                    "success": False,
                    "target": "https://example.test/api/users",
                },
            ],
            "handoffs": [],
        },
        "vulnerability_confirmation": {
            "findings": [
                {
                    "title": "SQL injection",
                    "type": "sqli",
                    "severity": "high",
                    "status": "confirmed",
                }
            ]
        },
    }

    result = orchestrator._stage_evidence_learning(context)

    assert target_memory.targets[0][2]["framework"] == "React"
    assert len(target_memory.fingerprints) == 1
    assert target_memory.endpoints[0][1].endswith("/api/users")
    assert [item[1]["success"] for item in target_memory.attacks] == [
        True,
        False,
    ]
    assert len(technique_memory.attempts) == 2
    assert {
        item["target_url"] for item in technique_memory.attempts
    } == {"https://example.test/api/users"}
    assert target_memory.vulnerabilities[0][1]["vuln_type"] == "sqli"
    assert result["learning_updates"] == [
        {"technique": "case-variation", "success": True},
        {"technique": "plain-payload", "success": False},
    ]


def test_unified_scanner_has_no_bare_requests_transport():
    source = inspect.getsource(core.unified_scanner)

    assert "import requests" not in source
    assert ".stealth_scan(" in source
    assert ".stealth_request(" in source


def test_orchestrator_loads_memory_and_persists_learning_updates(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    adapters = _adapters([])
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    result = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        modules=["api", "js"],
        policy="fast",
    )

    assert result["memo"]["target_seen"] is True
    assert result["learning_updates"][0]["technique"] == "case-variation"
    state = kernel.materialize(slug)
    assert state["learning_updates"][0]["success"] is True
    assert state["orchestrator"]["modules"] == ["api", "js"]


def test_evidence_registration_failure_remains_resumable_and_idempotent(
    tmp_path,
):
    class FailingEvidenceKernel(WorkflowKernel):
        def __init__(self, root):
            super().__init__(root)
            self.failures_remaining = 1

        def register_evidence(self, *args, **kwargs):
            if self.failures_remaining:
                self.failures_remaining -= 1
                raise OSError("evidence store unavailable")
            return super().register_evidence(*args, **kwargs)

    kernel = FailingEvidenceKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel, adapters=_adapters([])
    )

    first = orchestrator.orchestrate(
        slug, target_url="https://example.test"
    )

    assert first["status"] == "blocked"
    assert first["blocked_stage"] == "evidence_learning"
    state = kernel.materialize(slug)
    assert state["orchestrator"]["stage_status"]["evidence_learning"] != (
        "completed"
    )
    assert state["evidence"] == []
    assert state["findings"] == []

    resumed = orchestrator.resume(
        slug, target_url="https://example.test"
    )

    assert resumed["status"] == "completed"
    state = kernel.materialize(slug)
    assert len(state["evidence"]) == 1
    assert len(state["findings"]) == 1


def test_auto_pentest_tool_runs_passive_default_orchestrator(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )

    result = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                "https://example.test",
                {"policy": "fast", "modules": ["web"]},
            )
        )
    )

    assert result["status"] in {"ok", "awaiting_confirmation"}
    assert result["data"]["target_url"] == "https://example.test"
    assert "stage_results" in result["data"]
    assert result["data"]["execution"] == "deferred"


def test_auto_pentest_passes_browser_callback_across_worker_thread(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    observed = {}
    real_orchestrator = mcp_server.UnifiedOrchestrator

    class FakeUnifiedOrchestrator:
        _modules = staticmethod(real_orchestrator._modules)

        def __init__(self, kernel, services=None):
            observed["services"] = dict(services or {})

        def orchestrate(self, *args, **kwargs):
            observed["orchestrator_thread"] = threading.get_ident()
            caller = observed["services"]["call_mcp_tool"]
            observed["browser_result"] = asyncio.run(
                caller("playwright-mcp", "browser_snapshot", {})
            )
            return {
                "status": "completed",
                "stage_results": {},
                "execution": "completed",
            }

    async def run():
        observed["mcp_thread"] = threading.get_ident()

        async def caller(backend_name, tool_name, arguments):
            observed["callback_thread"] = threading.get_ident()
            observed["callback_call"] = (
                backend_name,
                tool_name,
                arguments,
            )
            return {"snapshot": "ok"}

        mcp_server._set_browser_mcp_caller(caller)
        monkeypatch.setattr(
            mcp_server,
            "UnifiedOrchestrator",
            FakeUnifiedOrchestrator,
        )
        try:
            return json.loads(
                await mcp_server.hunter_auto_pentest(
                    "https://example.test",
                    {"policy": "fast", "modules": ["web"]},
                )
            )
        finally:
            mcp_server._set_browser_mcp_caller(None)

    result = asyncio.run(run())

    assert result["status"] == "ok"
    assert observed["callback_call"] == (
        "playwright-mcp",
        "browser_snapshot",
        {},
    )
    assert observed["browser_result"] == {"snapshot": "ok"}
    assert observed["orchestrator_thread"] != observed["mcp_thread"]
    assert observed["callback_thread"] == observed["mcp_thread"]


def test_threadsafe_browser_callback_has_a_deadline(monkeypatch):
    async def run():
        async def never_returns(backend_name, tool_name, arguments):
            await asyncio.sleep(60)

        mcp_server._set_browser_mcp_caller(never_returns)
        monkeypatch.setattr(
            mcp_server,
            "BROWSER_MCP_CALL_TIMEOUT_SECONDS",
            0.01,
        )
        try:
            proxy = mcp_server._threadsafe_browser_mcp_caller(
                asyncio.get_running_loop()
            )
            with pytest.raises(asyncio.TimeoutError):
                await proxy("playwright-mcp", "browser_snapshot", {})
        finally:
            mcp_server._set_browser_mcp_caller(None)

    asyncio.run(run())


def test_auto_pentest_updates_mode_when_resuming_existing_target(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    target = "https://mode.example.test"
    first = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target, {"mode": "interactive"}
            )
        )
    )
    second = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {"mode": "autopilot", "resume": True},
            )
        )
    )

    assert second["data"]["workflow_slug"] == first["data"]["workflow_slug"]
    state = WorkflowKernel(tmp_path).materialize(
        second["data"]["workflow_slug"]
    )
    assert state["policy"]["mode"] == "autopilot"


def test_auto_pentest_creates_new_generation_when_configuration_changes(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    target = "https://generation.example.test"
    observations = {
        "stage_results": {
            "attack_execution": {"attempts": [], "handoffs": []}
        }
    }
    first = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {
                    "mode": "autopilot",
                    "policy": "fast",
                    "modules": ["web"],
                    "observations": observations,
                },
            )
        )
    )
    second = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {
                    "mode": "autopilot",
                    "policy": "deep",
                    "modules": ["reverse"],
                    "observations": observations,
                },
            )
        )
    )

    assert first["data"]["status"] == "completed"
    assert second["data"]["status"] == "completed"
    assert second["data"]["workflow_slug"] != first["data"]["workflow_slug"]
    assert second["data"]["generation"]["number"] == 2


def test_auto_pentest_fresh_run_creates_new_generation(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )
    target = "https://fresh.example.test"
    first = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target, {"mode": "autopilot"}
            )
        )
    )
    second = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                target,
                {
                    "mode": "autopilot",
                    "fresh_run": True,
                },
            )
        )
    )

    assert second["data"]["workflow_slug"] != first["data"]["workflow_slug"]
    assert second["data"]["generation"]["number"] == 2


def test_old_workflow_state_is_migrated_before_orchestrator_events(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    events_path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    event = json.loads(events_path.read_text(encoding="utf-8").strip())
    state = event["payload"]["state"]
    for key in (
        "orchestrator",
        "memo",
        "target_profile",
        "attack_surface",
        "attack_queue",
        "learning_updates",
        "report_path",
    ):
        state.pop(key, None)
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    event["event_hash"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    events_path.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")

    result = UnifiedOrchestrator(kernel, adapters=_adapters([])).orchestrate(
        slug,
        target_url="https://example.test",
        policy="fast",
    )

    assert result["status"] == "completed"
    assert kernel.materialize(slug)["orchestrator"]["current_stage"] == "complete"


def test_auto_attack_strategy_compiles_fingerprint_clues_and_waf_recommendations():
    class FakePatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {
                "primary": {
                    "name": "CAS + Java",
                    "description": "Common assessment issues: weak password.",
                    "follow_ups": ["Review SSO ticket handling."],
                    "confidence": 0.9,
                },
                "alternatives": [],
            }

    class FakeTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            return [
                {
                    "name": "case-variation",
                    "success_rate": 0.9,
                    "waf_type": waf_type,
                }
            ]

    class FakeFingerprintDatabase:
        @staticmethod
        def list(kind=""):
            return [
                {
                    "kind": "edu",
                    "name": "\u91d1\u667a CAS",
                    "default_endpoints": ["/lyuapServer/login"],
                    "auth": "campus SSO",
                    "cves": [],
                }
            ]

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": FakeTechniqueMemory(),
            "fingerprint_database": FakeFingerprintDatabase(),
        }
    )

    result = bridge._auto_attack_strategy(
        {"edu": "\u91d1\u667a CAS", "waf": "Cloudflare"}
    )

    weak_password = next(
        item
        for item in result
        if item["strategy_id"] == "weak_password_bruteforce"
    )
    assert weak_password["tool"] == "hunter_session_execute_chain"
    assert weak_password["tool_args"]["chain_name"] == "login_to_admin"
    assert weak_password["priority"] == "P0"
    assert "/lyuapServer/login" in (
        weak_password["title"] + weak_password["reason"]
    )
    assert any(item["strategy_id"] == "waf_case_variation" for item in result)


def test_auto_attack_strategy_preserves_each_product_clue_with_unique_ids():
    class EmptyPatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": EmptyPatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
        }
    )

    result = bridge._auto_attack_strategy({"cms": "WordPress"})
    wordpress = [
        item
        for item in result
        if "WordPress" in item["title"]
        and item.get("source") == "fingerprint_clue"
    ]

    assert len(wordpress) == 4
    assert len({item["strategy_id"] for item in wordpress}) == 4
    assert any("xmlrpc.php" in item["title"] for item in wordpress)
    assert any("wp-config.php.bak" in item["title"] for item in wordpress)

def test_auto_attack_strategy_uses_database_only_endpoints_and_cves():
    class EmptyPatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class DatabaseOnlyProduct:
        @staticmethod
        def list(kind=""):
            return [
                {
                    "kind": "cms",
                    "name": "Custom Acme CMS",
                    "default_endpoints": ["/acme-admin"],
                    "cves": ["CVE-2099-0001"],
                }
            ]

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": EmptyPatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
            "fingerprint_database": DatabaseOnlyProduct(),
        }
    )

    result = bridge._auto_attack_strategy({"cms": "Custom Acme CMS"})

    assert any(
        item["source"] == "fingerprint_database"
        and item["tool_args"].get("endpoint") == "/acme-admin"
        for item in result
    )
    assert any(
        item["source"] == "fingerprint_database"
        and "CVE-2099-0001" in item["title"]
        for item in result
    )


def test_auto_attack_strategy_falls_back_when_memory_queries_are_empty_or_fail():
    class EmptyPatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            return []

    class FailingPatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            raise RuntimeError("pattern database unavailable")

    class FailingTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            raise RuntimeError("technique database unavailable")

    for pattern_engine, technique_memory in (
        (EmptyPatternEngine(), EmptyTechniqueMemory()),
        (FailingPatternEngine(), FailingTechniqueMemory()),
    ):
        bridge = core.unified_scanner.UnifiedOrchestrationBridge(
            {
                "pattern_engine": pattern_engine,
                "technique_memory": technique_memory,
            }
        )

        result = bridge._auto_attack_strategy({"waf": "Unknown WAF"})

        assert result
        assert any(
            item["tool"] == "hunter_scan_plan"
            and item["strategy_id"] == "baseline_stack_scan"
            for item in result
        )


def test_attack_surface_survives_pattern_engine_failure():
    class FailingPatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            raise RuntimeError("pattern database unavailable")

        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FailingPatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
        }
    )
    result = bridge.stage_attack_surface(
        {
            "target_url": "https://example.test",
            "profile": {"max_endpoints": 20, "max_attack_surfaces": 5},
            "target_profile": {"fingerprints": {}},
        }
    )

    assert result["attack_queue"]
    assert result["attack_surface"]["stack_strategy"]["primary"] is None

def test_attack_surface_injects_sorted_strategy_items_without_breaking_legacy_queue():
    class FakePatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {}

        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class FakeTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": FakeTechniqueMemory(),
        }
    )
    context = {
        "target_url": "https://example.test",
        "profile": {"max_attack_surfaces": 10},
        "target_profile": {
            "fingerprints": {"cms": "WordPress"},
            "api_endpoints": [
                {
                    "url": "/api/search",
                    "method": "GET",
                    "parameters": ["query"],
                }
            ],
        },
    }

    result = bridge.stage_attack_surface(context)
    queue = result["attack_queue"]
    priorities = {
        "P0": 0,
        "P1": 1,
        "P2": 2,
    }

    assert queue
    assert any(item.get("strategy_id") for item in queue)
    assert any(item.get("kind") == "sqli" for item in queue)
    assert [
        priorities.get(item.get("priority", "P2"), 2)
        for item in queue
    ] == sorted(
        priorities.get(item.get("priority", "P2"), 2)
        for item in queue
    )
    strategy_ids = [
        item["strategy_id"]
        for item in queue
        if item.get("strategy_id")
    ]
    assert len(strategy_ids) == len(set(strategy_ids))


def test_attack_surface_fast_profile_preserves_discovered_endpoint():
    class FakePatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {}

        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": ["sqli"]}

    class FakeTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=10):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": FakeTechniqueMemory(),
        }
    )
    result = bridge.stage_attack_surface(
        {
            "target_url": "https://example.test",
            "profile": {"max_endpoints": 20, "max_attack_surfaces": 5},
            "target_profile": {
                "fingerprints": {"cms": "WordPress"},
                "api_endpoints": [
                    {
                        "url": "/api/search",
                        "method": "GET",
                        "parameters": ["query"],
                    }
                ],
            },
        }
    )

    assert len(result["attack_queue"]) == 5
    assert any(
        item.get("target") == "https://example.test/api/search"
        and item.get("kind") == "sqli"
        for item in result["attack_queue"]
    )

def test_attack_execution_honors_explicit_strategy_tool_arguments():
    class FakePatternEngine:
        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class FakeTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class FakeTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": FakeTechniqueMemory(),
            "target_memory": FakeTargetMemory(),
        }
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "authentication",
                    "target": "https://example.test/lyuapServer/login",
                    "method": "GET",
                    "parameters": [],
                    "strategy_id": "weak_password_bruteforce",
                    "tool": "hunter_session_execute_chain",
                    "tool_args": {
                        "chain_name": "login_to_admin",
                        "endpoint": "/lyuapServer/login",
                    },
                }
            ],
        }
    )

    handoff = next(
        item
        for item in result["handoffs"]
        if item.get("tool") == "hunter_session_execute_chain"
    )
    assert handoff["arguments"]["chain_name"] == "login_to_admin"
    assert set(handoff["arguments"]) == {"session_id", "chain_name", "params"}
    assert handoff["arguments"]["params"]["target_url"] == "https://example.test"
    assert handoff["arguments"]["params"]["login_path"] == "/lyuapServer/login"
    assert handoff["arguments"]["params"]["username"] == "${credentials.username}"
    assert handoff["arguments"]["params"]["password"] == "${credentials.password}"


def test_scan_plan_strategy_handoffs_use_supported_schema_only():
    class PatternEngine:
        @staticmethod
        def recommend_stack(fingerprints):
            return {
                "primary": {
                    "name": "Spring",
                    "description": "Prioritize exposed management surfaces",
                    "follow_ups": ["actuator", "env"],
                }
            }

        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class TechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return [{"name": "case-variation", "success_rate": 0.8}]

    class EmptyTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": PatternEngine(),
            "technique_memory": TechniqueMemory(),
            "target_memory": EmptyTargetMemory(),
        }
    )
    strategies = bridge._auto_attack_strategy(
        {"framework": "Spring", "waf": "Cloudflare"}
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": strategies,
        }
    )

    scan_handoffs = [
        item for item in result["handoffs"]
        if item.get("tool") == "hunter_scan_plan"
    ]
    assert scan_handoffs
    assert all(
        set(item["arguments"]) <= {"target", "mode", "phases"}
        for item in scan_handoffs
    )


def test_explicit_strategy_executes_with_injected_executor():
    calls = []

    def execute_chain(**arguments):
        calls.append(arguments)
        return {"status": "ok"}

    class FakePatternEngine:
        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class EmptyTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
            "target_memory": EmptyTargetMemory(),
            "hunter_session_execute_chain": execute_chain,
        }
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "session_id": "session-live",
            "profile": {"name": "standard", "mode": "guided"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "authentication",
                    "target": "https://example.test/lyuapServer/login",
                    "strategy_id": "weak_password_bruteforce",
                    "tool": "hunter_session_execute_chain",
                    "tool_args": {
                        "chain_name": "login_to_admin",
                        "endpoint": "/lyuapServer/login",
                    },
                }
            ],
        }
    )

    assert len(calls) == 1
    assert result["attempts"][0]["tool"] == "hunter_session_execute_chain"
    assert all(
        item["tool"] != "hunter_session_execute_chain"
        for item in result["handoffs"]
    )


def test_explicit_strategy_is_deferred_without_executor():
    class FakePatternEngine:
        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class EmptyTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
            "target_memory": EmptyTargetMemory(),
        }
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"name": "standard", "mode": "guided"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "authentication",
                    "target": "https://example.test/login",
                    "tool": "hunter_session_execute_chain",
                    "tool_args": {
                        "chain_name": "login_to_admin",
                        "endpoint": "/login",
                    },
                }
            ],
        }
    )

    assert result["attempts"] == []
    assert result["handoffs"][0]["reason"] == "executor_unavailable"


def test_attack_execution_merges_reasoned_strategies_and_deduplicates_ids():
    class FakePatternEngine:
        @staticmethod
        def match_parameter(parameter, context=""):
            return {"parameter": parameter, "vulnerability_types": []}

    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class EmptyTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "pattern_engine": FakePatternEngine(),
            "technique_memory": EmptyTechniqueMemory(),
            "target_memory": EmptyTargetMemory(),
        }
    )
    context = {
        "target_url": "https://cas.example.test",
        "profile": {"name": "standard"},
        "evidence": [{"type": "login_page", "summary": "CAS 登录页"}],
        "target_profile": {
            "target_type": "cas_authentication",
            "authentication": "cas_sso",
            "forms": [
                {
                    "action": "/lyuapServer/login",
                    "fields": ["username", "password"],
                }
            ],
            "api_endpoints": ["/lyuapServer/login"],
            "fingerprints": {"edu_system": "金智 CAS"},
        },
        "attack_queue": [
            {
                "strategy_id": "cas_default_creds",
                "title": "existing placeholder",
                "actions": [],
            }
        ],
    }

    result = bridge.stage_attack_execution(context)

    matching = [
        item
        for item in context["attack_queue"]
        if "cas_default_creds" in item.get("strategy_ids", [])
    ]
    assert matching
    assert len(
        {item["idempotency_key"] for item in context["attack_queue"]}
    ) == len(context["attack_queue"])
    assert any(
        item["tool"] == "hunter_session_execute_chain"
        and item["arguments"]["chain_name"] == "login_to_admin"
        for item in result["handoffs"]
    )
    assert any(item["tool"] == "hunter_auto_sqli" for item in result["handoffs"])



def test_reasoned_access_control_action_filters_non_mcp_metadata():
    queue = core.unified_scanner.UnifiedOrchestrationBridge._expand_reasoned_queue(
        [
            {
                "strategy_id": "system_session_followup",
                "title": "session follow-up",
                "condition": "JSESSIONID available",
                "actions": [
                    {
                        "tool": "hunter_auto_access_control",
                        "priority": "P0",
                        "params": {
                            "target": "https://example.test/system/",
                            "cookie": "JSESSIONID=abc",
                            "session_cookie": "JSESSIONID=abc",
                            "probe_path": "/system/",
                        },
                    }
                ],
            }
        ]
    )

    assert queue[0]["tool_args"] == {"cookie": "JSESSIONID=abc"}
    assert queue[0]["target"] == "https://example.test/system/"


def test_deferred_stage_waits_for_external_result_then_resume_consumes_it(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    adapters = _adapters([])
    adapters["attack_execution"] = lambda context: {
        "status": "deferred",
        "handoffs": [{"tool": "hunter_auto_sqli", "execution": "deferred"}],
    }
    orchestrator = UnifiedOrchestrator(kernel, adapters=adapters)

    pending = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        policy="standard",
    )

    assert pending["status"] == "awaiting_external"
    assert pending["current_stage"] == "attack_execution"
    assert pending["stage_results"]["attack_execution"]["handoffs"]

    resumed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        observations={
            "stage_results": {
                "attack_execution": {
                    "status": "completed",
                    "attempts": [{"technique": "case-variation", "success": True}],
                    "handoffs": [],
                }
            }
        },
    )
    assert resumed["status"] == "completed"
    assert resumed["learning_updates"][0]["technique"] == "case-variation"



def test_reasoned_queue_merge_preserves_completed_strategy_state():
    existing = [
        {
            "strategy_id": "cas_default_creds",
            "status": "completed",
            "actions": [{"tool": "hunter_scan_plan"}],
            "result": {"status": "ok"},
        }
    ]
    reasoned = [
        {
            "strategy_id": "cas_default_creds",
            "title": "new reasoning",
            "actions": [{"tool": "hunter_auto_sqli"}],
        }
    ]

    merged = core.unified_scanner.UnifiedOrchestrationBridge._merge_reasoned_queue(
        existing,
        reasoned,
    )

    assert merged == existing


def test_completed_reasoned_strategy_does_not_create_empty_deferred_stage():
    class EmptyTechniqueMemory:
        @staticmethod
        def best_for_waf(waf_type, limit=5):
            return []

    class EmptyTargetMemory:
        @staticmethod
        def query_target(target):
            return {"attack_history": []}

        @staticmethod
        def similar_targets(target, limit=5):
            return []

    bridge = core.unified_scanner.UnifiedOrchestrationBridge(
        {
            "technique_memory": EmptyTechniqueMemory(),
            "target_memory": EmptyTargetMemory(),
        }
    )
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {"name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "strategy_id": "finished",
                    "status": "completed",
                    "actions": [{"tool": "hunter_scan_plan"}],
                }
            ],
        }
    )

    assert result["status"] == "completed"
    assert result["handoffs"] == []


def test_blocked_attack_execution_persists_reasoned_queue_and_completion_keys(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    kernel._append(
        slug,
        "orchestrator.stage.blocked",
        {
            "stage": "attack_execution",
            "status": "awaiting_external",
            "result": {
                "status": "deferred",
                "attack_queue": [
                    {"strategy_id": "cas_default_creds", "actions": []}
                ],
                "completed_attacks": ["sqli|hunter_auto_sqli|https://example.test"],
                "handoffs": [{"tool": "hunter_auto_sqli"}],
            },
        },
    )

    state = kernel.materialize(slug)

    assert state["attack_queue"][0]["strategy_id"] == "cas_default_creds"
    assert state["completed_attacks"] == [
        "sqli|hunter_auto_sqli|https://example.test"
    ]


def test_checkpoint_resume_recovers_from_corrupt_event_tail(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = _workflow(kernel)
    orchestrator = UnifiedOrchestrator(
        kernel,
        adapters=_adapters([], pause_once=True),
    )
    interrupted = orchestrator.orchestrate(
        slug,
        target_url="https://example.test",
        policy="standard",
    )
    events_path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    with events_path.open("a", encoding="utf-8") as handle:
        handle.write('{"broken":')

    resumed = orchestrator.resume(
        slug,
        target_url="https://example.test",
        checkpoint_id=interrupted["checkpoint_id"],
    )

    assert resumed["status"] == "completed"
    assert json.loads(events_path.read_text(encoding="utf-8").splitlines()[-1])["type"] == "orchestrator.completed"
