from core.unified_scanner import OrchestratorRunner


class StubReasoner:
    def __init__(self):
        self.calls = []

    def reason(self, facts, evidence, memory):
        self.calls.append((facts, evidence, memory))
        return [
            {
                "strategy_id": "sqli-probe",
                "title": "Probe id",
                "condition": "id parameter discovered",
                "actions": [
                    {
                        "tool": "hunter_auto_sqli",
                        "priority": "P0",
                        "params": {
                            "target": "https://example.test/items",
                            "param": "id",
                        },
                    }
                ],
            }
        ]


class StubBridge:
    def __init__(self):
        self.services = {}
        self.execution_contexts = []

    def stage_memory(self, context):
        return {"memo": {"best_techniques": [{"name": "boolean-based"}]}}

    def stage_recon(self, context):
        return {
            "target_profile": {
                "target_type": "api",
                "authentication": "session_cookie",
                "api_endpoints": [
                    {
                        "url": "https://example.test/items",
                        "parameters": [{"name": "id"}],
                    }
                ],
                "params": [{"name": "id"}],
                "forms": [
                    {
                        "action": "/login",
                        "inputs": [{"name": "username"}, {"name": "password"}],
                    }
                ],
                "cookies": {"session": "abc"},
                "fingerprints": {"framework": "Django", "waf": "Cloudflare"},
                "captcha": {"type": "slider"},
            },
            "observations": [{"type": "parameter", "summary": "id"}],
        }

    def stage_attack_surface(self, context):
        return {"attack_queue": []}

    def stage_attack_execution(self, context):
        self.execution_contexts.append(context)
        strategy = context["strategies"][0]
        return {
            "status": "completed",
            "attempts": [
                {
                    "tool": strategy["actions"][0]["tool"],
                    "success": True,
                }
            ],
            "handoffs": [],
        }

    def stage_confirmation(self, context):
        return {"findings": [{"type": "sqli", "status": "confirmed"}]}

    def stage_evidence_learning(self, context):
        return {"evidence": [{"summary": "confirmed sqli"}]}


def test_runner_completes_all_six_stages_and_feeds_reasoning_to_execution():
    bridge = StubBridge()
    reasoner = StubReasoner()
    runner = OrchestratorRunner(bridge, object(), reasoner)

    result = runner.run("https://example.test")

    assert result["phases_completed"] == [
        "memory",
        "recon",
        "attack_surface",
        "attack_execution",
        "confirmation",
        "evidence_learning",
    ]
    assert result["strategies"][0]["strategy_id"] == "sqli-probe"
    assert result["attack_results"][0]["attempts"][0]["tool"] == "hunter_auto_sqli"
    assert bridge.execution_contexts[0]["strategies"] == result["strategies"]
    assert result["findings"][0]["status"] == "confirmed"
    assert result["errors"] == []


def test_build_facts_normalizes_recon_shapes():
    runner = OrchestratorRunner(StubBridge(), object(), StubReasoner())

    facts = runner._build_facts(
        {
            "target_url": "https://example.test",
            "target_profile": {
                "target_type": "api",
                "authentication": "jwt",
                "api_endpoints": [{"url": "/users", "parameters": ["id"]}],
                "params": {"redirect": "https://elsewhere.test"},
                "forms": [{"inputs": ["username", {"name": "password"}]}],
                "session_cookie": "sid=one; theme=dark",
                "fingerprints": {
                    "server": {"name": "nginx"},
                    "frameworks": ["Django", "DRF"],
                },
                "waf": "Cloudflare",
                "captcha": "recaptcha",
            },
        }
    )

    assert facts == {
        "target_url": "https://example.test",
        "target_type": "api",
        "authentication": "jwt",
        "captcha": "recaptcha",
        "waf": {"type": "Cloudflare", "confidence": 1.0},
        "endpoints": [{"url": "/users", "parameters": ["id"]}],
        "params": ["redirect"],
        "forms": [
            {
                "inputs": ["username", {"name": "password"}],
                "fields": ["username", {"name": "password"}],
            }
        ],
        "cookies": {"sid": "one", "theme": "dark"},
        "technologies": ["nginx", "Django", "DRF"],
    }


def test_runner_sorts_strategies_by_action_priority():
    class PriorityReasoner(StubReasoner):
        def reason(self, facts, evidence, memory):
            return [
                {"strategy_id": "later", "actions": [{"tool": "hunter_scan_plan", "priority": "P2"}]},
                {"strategy_id": "first", "actions": [{"tool": "hunter_auto_xss", "priority": "P0"}]},
            ]

    bridge = StubBridge()
    result = OrchestratorRunner(bridge, object(), PriorityReasoner()).run(
        "https://example.test"
    )

    assert [item["strategy_id"] for item in result["attack_results"]] == [
        "first",
        "later",
    ]


def test_hunter_auto_attack_exposes_runner_result(monkeypatch):
    import asyncio
    import json
    import mcp_server

    class FakeRunner:
        def run(self, target, options):
            return {
                "target_url": target,
                "options": options,
                "strategies": [{"strategy_id": "reasoned"}],
                "attack_results": [{"strategy_id": "reasoned", "status": "completed"}],
                "phases_completed": [
                    "memory",
                    "recon",
                    "attack_surface",
                    "attack_execution",
                    "confirmation",
                    "evidence_learning",
                ],
            }

    monkeypatch.setattr(mcp_server, "_orchestrator_runner", lambda caller=None: FakeRunner())

    result = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_attack(
                "https://example.test",
                '{"mode": "autopilot"}',
            )
        )
    )

    assert result["status"] == "success"
    assert result["strategies"][0]["strategy_id"] == "reasoned"
    assert result["attack_results"][0]["status"] == "completed"


def test_hunter_unified_scan_uses_orchestrator_runner(monkeypatch):
    import asyncio
    import json
    import mcp_server

    observed = {}

    class FakeRunner:
        def run(self, target, options):
            observed.update({"target": target, "options": options})
            return {"strategies": [], "attack_results": [], "phases_completed": []}

    monkeypatch.setattr(mcp_server, "_orchestrator_runner", lambda caller=None: FakeRunner())

    result = json.loads(
        asyncio.run(
            mcp_server.hunter_unified_scan(
                "https://example.test",
                cookie="sid=abc",
                collaborator="oob.test",
                phases=["recon", "sqli"],
            )
        )
    )

    assert result["status"] == "success"
    assert observed == {
        "target": "https://example.test",
        "options": {
            "session_cookie": "sid=abc",
            "collaborator": "oob.test",
            "requested_phases": ["recon", "sqli"],
        },
    }



def test_hunter_auto_pentest_can_opt_into_runner(tmp_path, monkeypatch):
    import asyncio
    import json
    import mcp_server

    monkeypatch.setattr(
        mcp_server,
        "_workspace",
        mcp_server.OpenTgtyLabWorkspaceAdapter(tmp_path),
    )

    class FakeRunner:
        def run(self, target, options):
            return {
                "target_url": target,
                "strategies": [{"strategy_id": "runner-strategy"}],
                "attack_results": [{"strategy_id": "runner-strategy"}],
                "stage_results": {},
                "phases_completed": [],
                "handoffs": [],
            }

    monkeypatch.setattr(mcp_server, "_orchestrator_runner", lambda caller=None: FakeRunner())

    result = json.loads(
        asyncio.run(
            mcp_server.hunter_auto_pentest(
                "https://example.test",
                {
                    "policy": "fast",
                    "mode": "autopilot",
                    "modules": ["web"],
                    "use_runner": True,
                },
            )
        )
    )

    assert result["status"] == "ok"
    assert result["data"]["strategies"][0]["strategy_id"] == "runner-strategy"
    assert result["data"]["attack_results"][0]["strategy_id"] == "runner-strategy"
