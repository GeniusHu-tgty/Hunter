import asyncio
import json

import mcp_server
from core.auto_idor import AutoIDOR
from core.evidence.verdict_engine import Evidence, Verdict, VerdictEngine, VulnType


class Response:
    def __init__(self, status, body, headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {"Content-Type": "application/json"}


class RouteSession:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        route = self.routes[url]
        if isinstance(route, list):
            return route.pop(0)
        return route

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


def body(resource_id, owner_id, request_id):
    return json.dumps(
        {
            "id": resource_id,
            "owner_id": owner_id,
            "amount": 9900,
            "request_id": request_id,
        }
    )


def build_sessions(probe_responses=None, anonymous_response=None):
    own_url = "https://target.test/api/orders/order-a"
    owner_url = "https://target.test/api/orders/order-b"
    owner_body = body("order-b", "user-b", "owner-control")
    probes = probe_responses or [
        Response(200, body("order-b", "user-b", f"probe-{index}"))
        for index in range(3)
    ]
    attacker = RouteSession(
        {
            own_url: Response(200, body("order-a", "user-a", "attacker-control")),
            owner_url: probes,
        }
    )
    owner = RouteSession({owner_url: Response(200, owner_body)})
    anonymous = RouteSession(
        {owner_url: anonymous_response or Response(403, '{"error":"forbidden"}')}
    )
    return attacker, owner, anonymous


def run_differential(attacker, owner, anonymous, repetitions=3):
    engine = AutoIDOR(
        "https://target.test/api/orders/{id}",
        session=attacker,
        session2=owner,
        anonymous_session=anonymous,
    )
    return engine.test_authorization_differential(
        url_template="https://target.test/api/orders/{id}",
        attacker_id="order-a",
        owner_id="order-b",
        attacker_cookie="sid=attacker-secret",
        owner_cookie="sid=owner-secret",
        repetitions=repetitions,
    )


def test_verified_cross_user_read_requires_owner_and_anonymous_controls():
    attacker, owner, anonymous = build_sessions()

    result = run_differential(attacker, owner, anonymous)

    assert result["vulnerable"] is True
    assert result["classification"] == "verified"
    assert result["controls"]["cross_user"]["semantic_matches"] == 3
    assert result["evidence"]["reproduction_count"] == 3
    assert result["evidence"]["metadata"]["request_user"] == "order-a"
    assert result["evidence"]["metadata"]["resource_owner"] == "order-b"
    assert result["evidence"]["metadata"]["owner_data_returned"] is True

    verdict = VerdictEngine().assess(
        VulnType.IDOR,
        Evidence.from_mapping(result["evidence"]),
    )
    assert verdict.verdict is Verdict.VERIFIED

    serialized = json.dumps(result)
    assert "attacker-secret" not in serialized
    assert "owner-secret" not in serialized
    assert result["evidence"]["request"]["headers"]["Cookie"] == "REDACTED"
    assert attacker.calls[0][2]["headers"]["Cookie"] == "sid=attacker-secret"
    assert owner.calls[0][2]["headers"]["Cookie"] == "sid=owner-secret"
    assert "Cookie" not in anonymous.calls[0][2].get("headers", {})


def test_public_resource_is_refuted_by_anonymous_control():
    public = Response(200, body("order-b", "user-b", "public-request"))
    attacker, owner, anonymous = build_sessions(anonymous_response=public)

    result = run_differential(attacker, owner, anonymous)

    assert result["vulnerable"] is False
    assert result["classification"] == "refuted"
    assert result["controls"]["anonymous"]["matches_owner"] is True
    assert "public" in result["reason"].lower()
    assert result["evidence"]["metadata"]["owner_data_returned"] is False
    verdict = VerdictEngine().assess(
        VulnType.IDOR,
        Evidence.from_mapping(result["evidence"]),
    )
    assert verdict.verdict is Verdict.REFUTED


def test_generic_identical_200_controls_are_not_reported_as_idor():
    generic = '{"ok":true,"message":"request accepted"}'
    own_url = "https://target.test/api/orders/order-a"
    owner_url = "https://target.test/api/orders/order-b"
    attacker = RouteSession(
        {
            own_url: Response(200, generic),
            owner_url: [Response(200, generic) for _ in range(3)],
        }
    )
    owner = RouteSession({owner_url: Response(200, generic)})
    anonymous = RouteSession({owner_url: Response(403, "forbidden")})

    result = run_differential(attacker, owner, anonymous)

    assert result["vulnerable"] is False
    assert result["classification"] == "refuted"
    assert result["controls"]["attacker_own"]["matches_owner"] is True
    assert "generic" in result["reason"].lower()


def test_owner_control_must_be_authenticated_and_successful():
    attacker, owner, anonymous = build_sessions()
    owner.routes["https://target.test/api/orders/order-b"] = Response(
        302,
        "login",
        {"Location": "/login"},
    )

    result = run_differential(attacker, owner, anonymous)

    assert result["vulnerable"] is False
    assert result["classification"] == "inconclusive"
    assert result["controls"]["cross_user"]["attempts"] == 0
    assert "owner control" in result["reason"].lower()


def test_all_reproductions_must_return_the_owner_resource():
    owner_body = body("order-b", "user-b", "owner")
    attacker, owner, anonymous = build_sessions(
        probe_responses=[
            Response(200, owner_body),
            Response(403, "forbidden"),
            Response(200, owner_body),
        ]
    )

    result = run_differential(attacker, owner, anonymous)

    assert result["vulnerable"] is False
    assert result["classification"] == "likely"
    assert result["controls"]["cross_user"]["semantic_matches"] == 2
    assert result["evidence"]["reproduction_count"] == 2
    assert result["evidence"]["metadata"]["owner_data_returned"] is True
    verdict = VerdictEngine().assess(
        VulnType.IDOR,
        Evidence.from_mapping(result["evidence"]),
    )
    assert verdict.verdict is Verdict.LIKELY


def test_volatile_fields_do_not_break_semantic_owner_matching():
    attacker, owner, anonymous = build_sessions()

    result = run_differential(attacker, owner, anonymous)

    owner_digest = result["controls"]["owner"]["semantic_digest"]
    assert result["controls"]["cross_user"]["semantic_digests"] == [
        owner_digest,
        owner_digest,
        owner_digest,
    ]


def test_short_numeric_id_must_match_an_identity_field_not_a_substring():
    attacker_url = "https://target.test/api/orders/9"
    owner_url = "https://target.test/api/orders/1"
    owner_body = '{"id":10,"amount":1,"message":"processed 1 item"}'
    attacker = RouteSession(
        {
            attacker_url: Response(200, '{"id":9,"amount":1}'),
            owner_url: [Response(200, owner_body) for _ in range(3)],
        }
    )
    owner = RouteSession({owner_url: Response(200, owner_body)})
    anonymous = RouteSession({owner_url: Response(403, "forbidden")})

    engine = AutoIDOR(
        "https://target.test/api/orders/{id}",
        session=attacker,
        session2=owner,
        anonymous_session=anonymous,
    )
    result = engine.test_authorization_differential(
        url_template="https://target.test/api/orders/{id}",
        attacker_id="9",
        owner_id="1",
        repetitions=3,
    )

    assert result["vulnerable"] is False
    assert result["classification"] == "inconclusive"
    assert "not bound" in result["reason"].lower()
    assert result["controls"]["cross_user"]["attempts"] == 0


def test_response_authentication_headers_are_redacted_from_evidence():
    attacker, owner, anonymous = build_sessions()
    attacker.routes["https://target.test/api/orders/order-a"] = Response(
        200,
        body("order-a", "user-a", "attacker-control"),
        {"Content-Type": "application/json", "Set-Cookie": "sid=baseline-secret"},
    )
    attacker.routes["https://target.test/api/orders/order-b"] = [
        Response(
            200,
            body("order-b", "user-b", f"probe-{index}"),
            {"Content-Type": "application/json", "Set-Cookie": "sid=probe-secret"},
        )
        for index in range(3)
    ]

    result = run_differential(attacker, owner, anonymous)

    serialized = json.dumps(result)
    assert "baseline-secret" not in serialized
    assert "probe-secret" not in serialized
    assert result["evidence"]["response"]["headers"]["Set-Cookie"] == "REDACTED"
    assert result["evidence"]["baseline_response"]["headers"]["Set-Cookie"] == "REDACTED"


def test_differential_requires_distinct_ids_and_an_id_template():
    attacker, owner, anonymous = build_sessions()
    engine = AutoIDOR(
        "https://target.test/api/orders/order-a",
        session=attacker,
        session2=owner,
        anonymous_session=anonymous,
    )

    missing_template = engine.test_authorization_differential(
        url_template="https://target.test/api/orders/order-a",
        attacker_id="order-a",
        owner_id="order-b",
    )
    same_identity = engine.test_authorization_differential(
        url_template="https://target.test/api/orders/{id}",
        attacker_id="order-a",
        owner_id="order-a",
    )

    assert missing_template["classification"] == "inconclusive"
    assert same_identity["classification"] == "inconclusive"
    assert not attacker.calls


def test_mcp_idor_wrapper_forwards_two_account_differential_inputs(monkeypatch):
    captured = {}

    async def fake_runner(tool_name, module, func, *args, **kwargs):
        captured.update(kwargs)
        return json.dumps({"status": "success"})

    monkeypatch.setattr(mcp_server, "_safe_auto_json_tool", fake_runner)

    asyncio.run(
        mcp_server.hunter_auto_idor(
            "https://target.test",
            endpoint="/api/orders/{id}",
            cookie="sid=attacker",
            owner_cookie="sid=owner",
            attacker_id="order-a",
            owner_id="order-b",
            repetitions=4,
        )
    )

    assert captured["cookie"] == "sid=attacker"
    assert captured["owner_cookie"] == "sid=owner"
    assert captured["attacker_id"] == "order-a"
    assert captured["owner_id"] == "order-b"
    assert captured["repetitions"] == 4
