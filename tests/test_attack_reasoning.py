from core.reasoning.attack_reasoning import AttackReasoner


def test_reasoner_exposes_at_least_fifteen_rules():
    reasoner = AttackReasoner()

    assert len(reasoner.rules) >= 15


def test_cas_login_page_generates_stateful_default_credential_strategy():
    reasoner = AttackReasoner()
    facts = {
        "target_url": "https://cas.example.test/lyuapServer/login",
        "target_type": "cas_authentication",
        "authentication": "cas_sso",
        "forms": [
            {
                "action": "/lyuapServer/login",
                "fields": ["username", "password", "execution"],
            }
        ],
        "endpoints": ["/lyuapServer/login"],
    }

    strategies = reasoner.reason(
        facts,
        [{"type": "login_page", "summary": "CAS 登录页完整渲染"}],
        {},
    )

    strategy = next(
        item for item in strategies if item["strategy_id"] == "cas_default_creds"
    )
    assert strategy["condition"] == "CAS 登录页 + 含 password 字段"
    assert strategy["actions"][0] == {
        "tool": "hunter_session_execute_chain",
        "chain": "login_to_admin",
        "priority": "P0",
        "params": {
            "target_url": "https://cas.example.test/lyuapServer/login",
            "username": "admin",
            "password": "admin@123",
            "login_path": "/lyuapServer/login",
        },
    }
    assert any(
        action["tool"] == "hunter_auto_sqli" and action["param"] == "username"
        for action in strategy["actions"]
    )


def test_slider_captcha_generates_bypass_sequence_before_operator_handoff():
    strategies = AttackReasoner().reason(
        {
            "target_url": "https://example.test/login",
            "captcha": {"type": "slider", "bypassable": False},
            "forms": [{"action": "/login", "fields": ["captcha", "password"]}],
        },
        [],
        {},
    )

    strategy = next(
        item for item in strategies if item["strategy_id"] == "slider_captcha_bypass"
    )
    assert [action["action"] for action in strategy["actions"]] == [
        "try_remove_captcha_param",
        "try_fixed_captcha_value",
        "try_reuse_session_captcha",
        "log_operator_required",
    ]
    assert [action["priority"] for action in strategy["actions"]] == [
        "P0",
        "P1",
        "P1",
        "P2",
    ]


def test_system_endpoint_with_jsessionid_generates_authenticated_follow_up():
    strategies = AttackReasoner().reason(
        {
            "target_url": "https://portal.example.test",
            "authentication": "session_cookie",
            "endpoints": ["/system/", "/login"],
            "cookies": {"JSESSIONID": "abc123"},
        },
        [
            {
                "type": "http_response",
                "summary": "/system/ 返回 200 但提示需要登录",
                "status_code": 200,
            }
        ],
        {},
    )

    strategy = next(
        item for item in strategies if item["strategy_id"] == "system_session_followup"
    )
    assert strategy["actions"][0]["params"]["session_cookie"] == (
        "JSESSIONID=abc123"
    )
    assert strategy["actions"][0]["params"]["probe_path"] == "/system/"


def test_reasoner_deduplicates_strategy_ids_and_uses_memory_recommendations():
    strategies = AttackReasoner().reason(
        {
            "target_url": "https://example.test",
            "waf": {"type": "Cloudflare", "confidence": 0.9},
            "technologies": ["Nginx"],
        },
        [],
        {
            "recommendations": [
                {"name": "case-variation", "success_rate": 0.8},
                {"name": "case-variation", "success_rate": 0.8},
            ]
        },
    )

    strategy_ids = [item["strategy_id"] for item in strategies]
    assert len(strategy_ids) == len(set(strategy_ids))
    assert "memory_waf_bypass" in strategy_ids


def test_reasoner_accepts_recon_inputs_field_shape():
    strategies = AttackReasoner().reason(
        {
            "target_url": "https://cas.example.test",
            "target_type": "cas_authentication",
            "forms": [
                {
                    "action": "/cas/login",
                    "inputs": ["username", "password", "execution"],
                }
            ],
        },
        [],
        {},
    )

    assert any(item["strategy_id"] == "cas_default_creds" for item in strategies)


def test_reasoner_is_deterministic_for_same_snapshot():
    facts = {
        "target_url": "https://example.test",
        "authentication": "jwt",
        "params": ["id", "url"],
        "technologies": ["Spring", "Nginx"],
    }
    evidence = [{"type": "http_response", "summary": "需要登录"}]
    memory = {}
    reasoner = AttackReasoner()

    assert reasoner.reason(facts, evidence, memory) == reasoner.reason(
        facts,
        evidence,
        memory,
    )
