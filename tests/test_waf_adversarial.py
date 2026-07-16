import json

from core.stealth.waf_adversarial import (
    HTTPObservation,
    HTTPRequestTemplate,
    ResponseOracle,
    SearchBudget,
    StealthWAFExecutor,
    WAFAdversarialEngine,
    WAFProfile,
)


def observation(status=200, body="ok", headers=None, elapsed_ms=10):
    return HTTPObservation(
        status_code=status,
        body=body,
        headers=headers or {},
        elapsed_ms=elapsed_ms,
    )


def signature_profile(waf_type="ModSecurity"):
    return WAFProfile(
        gate="signature",
        waf_type=waf_type,
        confidence=0.9,
        baseline={"classification": "pass", "status_code": 200},
        blocked={"classification": "signature", "status_code": 403},
    )


class QueueExecutor:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, request, strategy_id=None):
        self.calls.append((request, strategy_id))
        item = self.responses.pop(0)
        return item(request, strategy_id) if callable(item) else item


def test_profile_fingerprints_signature_gate_from_baseline_and_blocked_control():
    executor = QueueExecutor(
        [
            observation(200, '{"ok":true}'),
            observation(
                403,
                "Access denied with code 403 by ModSecurity",
                {"X-Mod-Security": "enabled"},
            ),
        ]
    )
    engine = WAFAdversarialEngine(executor)

    profile = engine.profile(
        HTTPRequestTemplate("GET", "https://lab.test/search?q=normal"),
        HTTPRequestTemplate("GET", "https://lab.test/search?q=blocked"),
    )

    assert profile.gate == "signature"
    assert profile.waf_type == "ModSecurity"
    assert profile.confidence >= 0.8
    assert len(executor.calls) == 2


def test_profile_distinguishes_soft_block_challenge_rate_and_session_failure():
    scenarios = [
        (
            observation(200, "normal"),
            observation(200, "Your request has been blocked by Web Application Firewall"),
            "soft_block",
        ),
        (
            observation(200, "normal"),
            observation(403, "Just a moment. Enable JavaScript and cookies to continue"),
            "challenge",
        ),
        (observation(200, "normal"), observation(429, "slow down"), "rate_limit"),
        (
            observation(403, "Access denied"),
            observation(403, "Access denied"),
            "session_or_fingerprint",
        ),
    ]

    for baseline, blocked, expected in scenarios:
        engine = WAFAdversarialEngine(QueueExecutor([baseline, blocked]))
        profile = engine.profile(
            HTTPRequestTemplate("GET", "https://lab.test/normal"),
            HTTPRequestTemplate("GET", "https://lab.test/probe"),
        )
        assert profile.gate == expected


def test_search_verifies_only_after_three_oracle_confirmations_within_budget():
    def response_for(_request, strategy_id):
        if strategy_id == "case-variation":
            return observation(403, "Access denied", {"X-Mod-Security": "1"})
        return observation(200, '{"backend":"reached","proof":"WAF-LAB-42"}')

    executor = QueueExecutor([response_for] * 4)
    engine = WAFAdversarialEngine(executor)
    request = HTTPRequestTemplate(
        "POST",
        "https://lab.test/query",
        headers={"Content-Type": "application/json"},
        body={"q": "blocked-expression"},
    )

    result = engine.search(
        request,
        profile=signature_profile(),
        oracle=ResponseOracle(body_marker="WAF-LAB-42", baseline_body='{"ok":true}'),
        budget=SearchBudget(max_requests=4, repetitions=3, max_consecutive_blocks=3),
        strategy_ids=["case-variation", "comment-separation"],
    )

    assert result.verdict == "verified"
    assert result.verified is True
    assert result.strategy_id == "comment-separation"
    assert result.reproduction_count == 3
    assert result.requests_used == 4
    assert [call[1] for call in executor.calls] == [
        "case-variation",
        "comment-separation",
        "comment-separation",
        "comment-separation",
    ]


def test_waf_pass_without_backend_oracle_signal_is_not_a_verified_bypass():
    executor = QueueExecutor([observation(200, '{"message":"generic success"}')])
    engine = WAFAdversarialEngine(executor)

    result = engine.search(
        HTTPRequestTemplate("GET", "https://lab.test/?q=blocked"),
        profile=signature_profile(),
        oracle=ResponseOracle(body_marker="backend-proof", baseline_body="normal"),
        budget=SearchBudget(max_requests=1, repetitions=3),
        strategy_ids=["percent-encoding"],
    )

    assert result.verified is False
    assert result.bypass_found is True
    assert result.verdict == "inconclusive"
    assert result.outcomes[0]["transport_passed"] is True
    assert result.outcomes[0]["oracle_confirmed"] is False


def test_partial_proof_is_likely_but_cannot_cross_three_repeat_gate():
    executor = QueueExecutor(
        [
            observation(200, "backend-proof"),
            observation(200, "backend-proof"),
        ]
    )
    engine = WAFAdversarialEngine(executor)

    result = engine.search(
        HTTPRequestTemplate("GET", "https://lab.test/?q=blocked"),
        profile=signature_profile(),
        oracle=ResponseOracle(body_marker="backend-proof", baseline_body="normal"),
        budget=SearchBudget(max_requests=2, repetitions=3),
        strategy_ids=["percent-encoding"],
    )

    assert result.verified is False
    assert result.verdict == "likely"
    assert result.reproduction_count == 2
    assert result.requests_used == 2


def test_consecutive_blocks_stop_search_without_exceeding_budget():
    executor = QueueExecutor([observation(403, "Access denied")] * 10)
    engine = WAFAdversarialEngine(executor)

    result = engine.search(
        HTTPRequestTemplate("GET", "https://lab.test/?q=blocked"),
        profile=signature_profile(),
        oracle=ResponseOracle(body_marker="proof"),
        budget=SearchBudget(
            max_requests=8,
            repetitions=3,
            max_consecutive_blocks=2,
        ),
        strategy_ids=["one", "two", "three", "four"],
    )

    assert result.requests_used == 2
    assert result.stop_reason == "consecutive_block_limit"
    assert len(executor.calls) == 2


def test_duplicate_strategy_ids_are_executed_only_once():
    executor = QueueExecutor([observation(403, "Access denied")] * 3)
    engine = WAFAdversarialEngine(executor)

    engine.search(
        HTTPRequestTemplate("GET", "https://lab.test/?q=blocked"),
        profile=signature_profile(),
        oracle=ResponseOracle(body_marker="proof"),
        budget=SearchBudget(max_requests=3, repetitions=3, max_consecutive_blocks=5),
        strategy_ids=["one", "one", "two", "two", "three"],
    )

    assert [call[1] for call in executor.calls] == ["one", "two", "three"]


def test_response_oracle_supports_json_pointer_and_baseline_delta():
    baseline = observation(200, '{"data":{"executed":false}}')
    oracle = ResponseOracle(
        json_pointer="/data/executed",
        expected=True,
        baseline_body=baseline.body,
    )

    positive = oracle(
        HTTPRequestTemplate("POST", "https://lab.test/action"),
        observation(200, '{"data":{"executed":true}}'),
    )
    collision = ResponseOracle(
        body_marker="already-here",
        baseline_body="already-here",
    )(
        HTTPRequestTemplate("GET", "https://lab.test/"),
        observation(200, "already-here"),
    )

    assert positive.confirmed is True
    assert positive.signal == "json_pointer_match"
    assert collision.confirmed is False
    assert collision.reason == "oracle signal already existed in baseline"


def test_result_evidence_redacts_request_and_response_secrets():
    executor = QueueExecutor(
        [
            observation(
                200,
                '{"proof":"backend-proof","token":"response-secret"}',
                {"Set-Cookie": "sid=response-cookie-secret"},
            )
        ]
    )
    request = HTTPRequestTemplate(
        "POST",
        "https://lab.test/action",
        headers={
            "Authorization": "Bearer request-token-secret",
            "Cookie": "sid=request-cookie-secret",
            "X-Trace": "safe",
        },
        body={"password": "body-password-secret", "q": "payload"},
    )
    result = WAFAdversarialEngine(executor).search(
        request,
        profile=signature_profile(),
        oracle=ResponseOracle(body_marker="backend-proof"),
        budget=SearchBudget(max_requests=1, repetitions=3),
        strategy_ids=["percent-encoding"],
    )

    serialized = json.dumps(result.to_dict())
    for secret in (
        "request-token-secret",
        "request-cookie-secret",
        "response-cookie-secret",
        "body-password-secret",
        "response-secret",
    ):
        assert secret not in serialized
    evidence_request = result.to_dict()["evidence"]["request"]
    assert evidence_request["headers"]["Authorization"] == "REDACTED"
    assert evidence_request["body"]["password"] == "REDACTED"


def test_stealth_executor_preserves_template_and_disables_automatic_retries():
    class Client:
        def __init__(self):
            self.calls = []

        def stealth_request(self, method, url, headers=None, data=None, options=None):
            self.calls.append((method, url, headers, data, options))
            return {
                "status": "ok",
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": '{"proof":"ok"}',
                "timeline": [{"elapsed": 0.02}],
            }

    client = Client()
    executor = StealthWAFExecutor(client)
    request = HTTPRequestTemplate(
        "POST",
        "https://lab.test/api",
        headers={"Content-Type": "application/json", "X-Test": "1"},
        body={"q": "value"},
    )

    result = executor(request, "content-type-rotation")

    assert result.status_code == 200
    method, url, headers, body, options = client.calls[0]
    assert (method, url, headers, body) == (
        request.method,
        request.url,
        request.headers,
        request.body,
    )
    assert options["max_retries"] == 0
    assert options["follow_redirects"] is False
    assert options["initial_strategy"]["id"] == "content-type-rotation"


def test_invalid_search_budget_is_rejected_before_execution():
    executor = QueueExecutor([observation(200, "proof")])
    engine = WAFAdversarialEngine(executor)

    try:
        engine.search(
            HTTPRequestTemplate("GET", "https://lab.test/"),
            profile=signature_profile(),
            oracle=ResponseOracle(body_marker="proof"),
            budget=SearchBudget(max_requests=0, repetitions=3),
            strategy_ids=["one"],
        )
    except ValueError as exc:
        assert "max_requests" in str(exc)
    else:
        raise AssertionError("invalid budget was accepted")
    assert executor.calls == []
