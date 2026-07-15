from core.workflow.action_planner import ActionPlanner


def action(tool, kind, target="https://example.test", priority="P1"):
    return {
        "tool": tool,
        "kind": kind,
        "target": target,
        "arguments": {"target": target},
        "priority": priority,
    }


def test_planner_merges_same_action_and_preserves_both_sources():
    planner = ActionPlanner()
    result = planner.plan(
        [action("hunter_auto_sqli", "sqli")],
        [
            {
                "strategy_id": "reasoned",
                "actions": [
                    {
                        "tool": "hunter_auto_sqli",
                        "priority": "P0",
                        "params": {"target": "https://example.test"},
                    }
                ],
            }
        ],
    )

    assert len(result["actions"]) == 1
    assert set(result["actions"][0]["sources"]) == {
        "attack-surface",
        "reasoner",
    }
    assert result["actions"][0]["priority"] == "P0"


def test_planner_keeps_general_queue_when_reasoner_is_empty():
    result = ActionPlanner().plan(
        [action("hunter_auto_xss", "xss")],
        [],
    )

    assert [item["tool"] for item in result["actions"]] == [
        "hunter_auto_xss"
    ]


def test_planner_filters_module_before_spending_budget():
    result = ActionPlanner().plan(
        [
            action("hunter_auto_xss", "xss", priority="P0"),
            action("hunter_auto_sqli", "sqli", priority="P1"),
        ],
        [],
        modules=["sqli"],
        max_actions=1,
    )

    assert [item["kind"] for item in result["actions"]] == ["sqli"]
    assert result["budget"]["started_actions"] == 1
    assert result["filtered_actions"][0]["reason"] == "module_excluded"


def test_planner_respects_requested_recon_only_phase():
    result = ActionPlanner().plan(
        [action("hunter_auto_sqli", "sqli")],
        [],
        requested_phases=["recon"],
    )

    assert result["actions"] == []
    assert result["filtered_actions"][0]["reason"] == "phase_excluded"


def test_planner_does_not_repeat_completed_idempotency_key():
    planner = ActionPlanner()
    first = planner.plan(
        [action("hunter_auto_sqli", "sqli")],
        [],
    )
    key = first["actions"][0]["idempotency_key"]
    second = planner.plan(
        [action("hunter_auto_sqli", "sqli")],
        [],
        completed_keys=[key],
    )

    assert second["actions"] == []
    assert second["filtered_actions"][0]["reason"] == "already_completed"
