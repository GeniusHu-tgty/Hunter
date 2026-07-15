from core.memory.technique_memory import TechniqueMemory
from core.unified_scanner import (
    OrchestratorRunner,
    UnifiedOrchestrationBridge,
)


class EmptyMemory:
    def best_for_waf(self, waf_type, limit=5):
        return []

    def query_target(self, target):
        return {"attack_history": []}

    def similar_targets(self, target, limit=5):
        return []


class EmptyReasoner:
    def reason(self, facts, evidence, memory):
        return []


def bridge_with_runner(runner, technique_memory=None):
    memory = EmptyMemory()
    return UnifiedOrchestrationBridge(
        {
            "auto_tool_runner": runner,
            "technique_memory": technique_memory or memory,
            "target_memory": memory,
        }
    )


def test_explicit_reasoner_action_executes_when_executor_is_injected():
    calls = []

    def runner(tool_name, arguments):
        calls.append((tool_name, dict(arguments)))
        return {
            "status": "ok",
            "data": {
                "vulnerable": False,
                "status_code": 200,
                "evidence": {
                    "request": {"url": arguments["target"]},
                    "response": {"status_code": 200, "body": "normal"},
                    "baseline_response": {
                        "status_code": 200,
                        "body": "normal",
                    },
                    "payload": "'",
                    "reproduction_count": 1,
                },
            },
        }

    bridge = bridge_with_runner(runner)
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test/search?q=1",
            "profile": {"mode": "autopilot", "name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [],
            "strategies": [
                {
                    "strategy_id": "reasoned-sqli",
                    "title": "verify q",
                    "condition": "q parameter",
                    "actions": [
                        {
                            "tool": "hunter_auto_sqli",
                            "priority": "P0",
                            "param": "q",
                            "params": {
                                "target_url": (
                                    "https://example.test/search?q=1"
                                )
                            },
                        }
                    ],
                }
            ],
        }
    )

    assert [name for name, _ in calls] == ["hunter_auto_sqli"]
    assert len(result["attempts"]) == 1
    assert result["handoffs"] == []


def test_empty_reasoner_falls_back_to_general_attack_queue():
    executed = []

    class QueueBridge:
        services = {}

        def stage_memory(self, context):
            return {"memo": {"best_techniques": []}}

        def stage_recon(self, context):
            return {"observations": []}

        def stage_attack_surface(self, context):
            return {
                "attack_queue": [
                    {
                        "kind": "xss",
                        "tool": "hunter_auto_xss",
                        "target": "https://example.test/?q=hello",
                        "parameters": ["q"],
                        "priority": "P0",
                    }
                ]
            }

        def stage_attack_execution(self, context):
            executed.extend(context["attack_queue"])
            return {
                "status": "completed",
                "attempts": [{"tool": "hunter_auto_xss"}],
                "handoffs": [],
            }

        def stage_confirmation(self, context):
            return {"findings": [], "verdicts": []}

        def stage_evidence_learning(self, context):
            return {"evidence": [], "learning_updates": []}

    result = OrchestratorRunner(
        QueueBridge(),
        object(),
        EmptyReasoner(),
    ).run("https://example.test")

    assert [item["tool"] for item in executed] == ["hunter_auto_xss"]
    assert result["stage_results"]["attack_execution"]["attempts"]


def test_http_200_with_vulnerable_false_is_not_technique_success(tmp_path):
    memory = TechniqueMemory(tmp_path / "memory.db")

    def runner(tool_name, arguments):
        return {
            "status": "ok",
            "data": {
                "status_code": 200,
                "vulnerable": False,
                "evidence": {
                    "request": {"url": arguments["target"]},
                    "response": {"status_code": 200, "body": "normal"},
                    "baseline_response": {
                        "status_code": 200,
                        "body": "normal",
                    },
                    "payload": "'",
                    "reproduction_count": 1,
                },
            },
        }

    bridge = bridge_with_runner(runner, technique_memory=memory)
    execution = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test/?id=1",
            "profile": {"mode": "autopilot", "name": "standard"},
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "sqli",
                    "target": "https://example.test/?id=1",
                    "parameters": ["id"],
                }
            ],
        }
    )

    attempt = execution["attempts"][0]
    assert attempt["transport_success"] is True
    assert attempt["probe_executed"] is True
    assert attempt["vulnerability_confirmed"] is False
    assert memory.attempts(technique_name="hunter_auto_sqli") == []


def test_baseline_sql_error_cannot_be_confirmed():
    bridge = bridge_with_runner(lambda *_: {})
    result = bridge.stage_confirmation(
        {
            "target_url": "https://example.test/?id=1",
            "stage_results": {
                "attack_execution": {
                    "attempts": [
                        {
                            "action_id": "act-sqli",
                            "tool": "hunter_auto_sqli",
                            "attack_surface": "sqli",
                            "target": "https://example.test/?id=1",
                            "response": {
                                "data": {
                                    "vulnerable": False,
                                    "evidence": {
                                        "request": {
                                            "url": (
                                                "https://example.test/?id=1'"
                                            )
                                        },
                                        "response": {
                                            "status_code": 500,
                                            "body": (
                                                "You have an error in your "
                                                "SQL syntax"
                                            ),
                                        },
                                        "baseline_response": {
                                            "status_code": 500,
                                            "body": (
                                                "You have an error in your "
                                                "SQL syntax"
                                            ),
                                        },
                                        "payload": "'",
                                        "reproduction_count": 3,
                                    },
                                }
                            },
                        }
                    ]
                }
            },
        }
    )

    assert result["findings"] == []
    assert result["verdicts"][0]["verdict"] in {
        "refuted",
        "inconclusive",
    }


def test_requested_modules_phases_and_budget_limit_real_execution():
    calls = []

    def runner(tool_name, arguments):
        calls.append(tool_name)
        return {"status": "ok", "data": {"vulnerable": False}}

    bridge = bridge_with_runner(runner)
    result = bridge.stage_attack_execution(
        {
            "target_url": "https://example.test",
            "profile": {
                "mode": "autopilot",
                "name": "standard",
                "modules": ["sqli"],
                "requested_phases": ["vulnerability-analysis"],
                "max_tool_calls": 1,
            },
            "target_profile": {"fingerprints": {}},
            "attack_queue": [
                {
                    "kind": "sqli",
                    "tool": "hunter_auto_sqli",
                    "target": "https://example.test/?id=1",
                    "parameters": ["id"],
                    "priority": "P0",
                },
                {
                    "kind": "xss",
                    "tool": "hunter_auto_xss",
                    "target": "https://example.test/?q=x",
                    "parameters": ["q"],
                    "priority": "P1",
                },
            ],
        }
    )

    assert calls == ["hunter_auto_sqli"]
    assert result["budget"]["started_actions"] == 1
    assert result["filtered_actions"][0]["reason"] == "module_excluded"
