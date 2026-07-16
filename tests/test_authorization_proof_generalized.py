import json

from core.auto_idor import AuthorizationProofPlan, Identity, verify_authorization_plan
from core.evidence.verdict_engine import Evidence, Verdict, VerdictEngine, VulnType


class Response:
    def __init__(self, status, body):
        self.status_code = status
        self.text = json.dumps(body) if isinstance(body, dict) else body
        self.headers = {"Content-Type": "application/json"}


class StatefulGraphQLSession:
    def __init__(self, token, state):
        self.token = token
        self.state = state
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        document = kwargs["json"]
        variables = document["variables"]
        resource_id = variables["input"]["orderId"]
        if "orderState" in document["query"]:
            return Response(200, {"data": {"order": {"status": self.state[resource_id]}}})
        if "reopenOrder" in document["query"]:
            self.state[resource_id] = "open"
            return Response(200, {"data": {"reopenOrder": {"ok": True}}})
        if self.token == "owner-token":
            self.state[resource_id] = "cancelled"
            return Response(200, {"data": {"cancelOrder": {"ok": True}}})
        if self.token == "attacker-token":
            self.state[resource_id] = "cancelled"
            return Response(200, {"data": {"cancelOrder": {"ok": True}}})
        return Response(403, {"errors": [{"message": "forbidden"}]})


def test_graphql_bola_write_requires_controls_state_oracle_and_reproduction():
    state = {"attacker-order": "open", "owner-order": "open"}
    attacker = StatefulGraphQLSession("attacker-token", state)
    owner = StatefulGraphQLSession("owner-token", state)
    anonymous = StatefulGraphQLSession("anonymous", state)
    plan = AuthorizationProofPlan(
        request_template={
            "method": "POST",
            "url": "https://target.test/graphql",
            "json": {
                "query": "mutation cancel($input: CancelInput!) { cancelOrder(input: $input) { ok } }",
                "variables": {"input": {"orderId": "{{resource_id}}"}},
            },
        },
        oracle_template={
            "method": "POST",
            "url": "https://target.test/graphql",
            "json": {
                "query": "query orderState($input: OrderInput!) { order(input: $input) { status } }",
                "variables": {"input": {"orderId": "{{resource_id}}"}},
            },
            "json_pointer": "/data/order/status",
            "expected_after": "cancelled",
        },
        cleanup_template={
            "method": "POST",
            "url": "https://target.test/graphql",
            "json": {
                "query": "mutation reopen($input: OrderInput!) { reopenOrder(input: $input) { ok } }",
                "variables": {"input": {"orderId": "{{resource_id}}"}},
            },
        },
        attacker=Identity("attacker", bearer_token="attacker-token", resource_id="attacker-order"),
        owner=Identity("owner", bearer_token="owner-token", resource_id="owner-order"),
        anonymous=Identity("anonymous"),
        repetitions=3,
        operation="write",
    )

    result = verify_authorization_plan(plan, {
        "attacker": attacker,
        "owner": owner,
        "anonymous": anonymous,
    })

    assert result["classification"] == "verified"
    assert result["vulnerability_type"] == "bola"
    assert result["evidence"]["reproduction_count"] == 3
    assert result["controls"]["owner"]["allowed"] is True
    assert result["controls"]["anonymous"]["denied"] is True
    assert all(round_["oracle_before"] == "open" for round_ in result["rounds"])
    assert all(round_["oracle_after"] == "cancelled" for round_ in result["rounds"])
    assert all(call[2]["headers"]["Authorization"] == "Bearer attacker-token" for call in attacker.calls if "cancelOrder" in call[2]["json"]["query"])
    assert "attacker-token" not in json.dumps(result)
    verdict = VerdictEngine().assess(VulnType.IDOR, Evidence.from_mapping(result["evidence"]))
    assert verdict.verdict is Verdict.VERIFIED


def test_bfla_proof_preserves_the_functional_authorization_category():
    state = {"user-action": "open", "admin-action": "open"}
    attacker = StatefulGraphQLSession("attacker-token", state)
    owner = StatefulGraphQLSession("owner-token", state)
    anonymous = StatefulGraphQLSession("anonymous", state)
    plan = AuthorizationProofPlan(
        request_template={"method": "POST", "url": "https://target.test/graphql", "json": {
            "query": "mutation cancel($input: CancelInput!) { cancelOrder(input: $input) { ok } }",
            "variables": {"input": {"orderId": "{{resource_id}}"}},
        }},
        oracle_template={"method": "POST", "url": "https://target.test/graphql", "json": {
            "query": "query orderState($input: OrderInput!) { order(input: $input) { status } }",
            "variables": {"input": {"orderId": "{{resource_id}}"}},
        }, "json_pointer": "/data/order/status", "expected_after": "cancelled"},
        cleanup_template={"method": "POST", "url": "https://target.test/graphql", "json": {
            "query": "mutation reopen($input: OrderInput!) { reopenOrder(input: $input) { ok } }",
            "variables": {"input": {"orderId": "{{resource_id}}"}},
        }},
        attacker=Identity("member", bearer_token="attacker-token", resource_id="user-action"),
        owner=Identity("admin", bearer_token="owner-token", resource_id="admin-action"),
        anonymous=Identity("anonymous"),
        repetitions=3,
        operation="write",
        vulnerability_type="bfla",
    )

    result = verify_authorization_plan(plan, {"attacker": attacker, "owner": owner, "anonymous": anonymous})

    assert result["classification"] == "verified"
    assert result["vulnerability_type"] == "bfla"
