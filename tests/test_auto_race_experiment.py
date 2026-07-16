import asyncio
import json

import mcp_server
from core import auto_race
from core.evidence.verdict_engine import Evidence, Verdict, VerdictEngine, VulnType


class StatefulRaceTransport:
    def __init__(self, mode="race_vulnerable"):
        self.mode = mode
        self.value = 0
        self.calls = []
        self.oracle_reads = 0

    async def request(self, spec, *, phase, index=0):
        self.calls.append((phase, index, dict(spec)))
        url = spec["url"]
        if url.endswith("/reset"):
            self.value = 0
            return {"status": 204, "body": "", "headers": {}}
        if url.endswith("/state"):
            self.oracle_reads += 1
            if self.mode == "unstable_oracle":
                self.value += 1
            return {
                "status": 200,
                "body": json.dumps({"credits_used": self.value}),
                "headers": {"Content-Type": "application/json"},
            }
        if url.endswith("/redeem"):
            if self.mode == "race_vulnerable":
                if phase == "control":
                    self.value = min(1, self.value + 1)
                elif phase == "race":
                    self.value += 1
            elif self.mode == "always_increments":
                self.value += 1
            elif self.mode == "no_effect":
                pass
            return {
                "status": 302,
                "body": "",
                "headers": {"Location": "/account"},
            }
        raise AssertionError(f"unexpected URL: {url}")


def experiment(transport, *, reset=True, rounds=3, copies=5, oracle=None):
    return auto_race.run_race_experiment(
        target="https://target.test/redeem",
        request_spec={
            "method": "POST",
            "url": "https://target.test/redeem",
            "headers": {
                "Authorization": "Bearer race-secret",
                "Content-Type": "application/json",
            },
            "json": {"coupon": "BOUNTY"},
        },
        oracle_spec=oracle or {
            "method": "GET",
            "url": "https://target.test/state",
            "json_pointer": "/credits_used",
            "direction": "increase",
            "maximum_effects": 1,
            "stable_reads": 2,
            "settle_timeout_ms": 100,
            "settle_interval_ms": 0,
            "max_dispatch_skew_ms": 100,
        },
        reset_spec=(
            {"method": "POST", "url": "https://target.test/reset"}
            if reset
            else {}
        ),
        session_cookie="sid=attacker",
        copies=copies,
        rounds=rounds,
        transport=transport,
    )


def test_canonical_race_evidence_id_excludes_artifact_content_hashes():
    evidence_id = auto_race.canonical_evidence_id("wf-1", 2, "action-1", "attempt-1", "race")

    assert evidence_id == "wf-1:2:action-1:attempt-1:race"


def test_duplicate_commit_is_verified_by_control_race_oracle_for_three_rounds():
    transport = StatefulRaceTransport()

    result = experiment(transport)

    assert result["classification"] == "verified"
    assert result["vulnerable"] is True
    assert len(result["rounds"]) == 3
    assert all(item["control_effect"] == 1 for item in result["rounds"])
    assert all(item["race_effect"] == 5 for item in result["rounds"])
    assert all(item["invariant_violated"] is True for item in result["rounds"])
    assert result["evidence"]["reproduction_count"] == 3

    verdict = VerdictEngine().assess(
        VulnType.RACE,
        Evidence.from_mapping(result["evidence"]),
    )
    assert verdict.verdict is Verdict.VERIFIED


def test_parallel_redirects_without_server_side_effect_are_refuted():
    result = experiment(StatefulRaceTransport(mode="no_effect"))

    assert result["classification"] == "refuted"
    assert result["vulnerable"] is False
    assert all(item["race_statuses"] == [302] * 5 for item in result["rounds"])
    assert all(item["race_effect"] == 0 for item in result["rounds"])
    assert result["evidence"]["metadata"]["invariant_violated"] is False


def test_broken_sequential_control_cannot_be_attributed_to_a_race():
    result = experiment(StatefulRaceTransport(mode="always_increments"))

    assert result["classification"] == "inconclusive"
    assert result["vulnerable"] is False
    assert all(item["control_effect"] == 5 for item in result["rounds"])
    assert all(item["control_normal"] is False for item in result["rounds"])
    assert "control" in result["reason"].lower()


def test_reset_is_required_for_comparable_control_and_race_initial_state():
    transport = StatefulRaceTransport()

    result = experiment(transport, reset=False)

    assert result["classification"] == "inconclusive"
    assert "reset" in result["reason"].lower()
    assert not [call for call in transport.calls if call[0] in {"control", "race"}]


def test_unstable_oracle_never_produces_a_verified_race():
    oracle = {
        "method": "GET",
        "url": "https://target.test/state",
        "json_pointer": "/credits_used",
        "direction": "increase",
        "maximum_effects": 1,
        "stable_reads": 3,
        "settle_timeout_ms": 2,
        "settle_interval_ms": 0,
        "max_dispatch_skew_ms": 100,
    }

    result = experiment(
        StatefulRaceTransport(mode="unstable_oracle"),
        oracle=oracle,
    )

    assert result["classification"] == "inconclusive"
    assert result["vulnerable"] is False
    assert result["evidence"]["metadata"]["oracle_stable"] is False


def test_request_credentials_are_used_but_redacted_from_evidence():
    transport = StatefulRaceTransport()

    result = experiment(transport)

    action_calls = [call for call in transport.calls if call[0] in {"control", "race"}]
    assert action_calls
    assert all(call[2]["headers"]["Cookie"] == "sid=attacker" for call in action_calls)
    assert all(call[2]["headers"]["Authorization"] == "Bearer race-secret" for call in action_calls)
    serialized = json.dumps(result)
    assert "sid=attacker" not in serialized
    assert "race-secret" not in serialized
    assert result["evidence"]["request"]["headers"]["Cookie"] == "REDACTED"
    assert result["evidence"]["request"]["headers"]["Authorization"] == "REDACTED"


def test_mcp_race_wrapper_forwards_experiment_specs(monkeypatch):
    captured = {}

    async def fake_runner(tool_name, module, func, *args, **kwargs):
        captured.update(kwargs)
        return json.dumps({"status": "success"})

    monkeypatch.setattr(mcp_server, "_safe_auto_json_tool", fake_runner)

    asyncio.run(
        mcp_server.hunter_auto_race(
            "https://target.test/redeem",
            cookie="sid=a",
            request_spec='{"method":"POST"}',
            oracle_spec='{"url":"https://target.test/state"}',
            reset_spec='{"url":"https://target.test/reset"}',
            copies=7,
            rounds=4,
        )
    )

    assert captured["session_cookie"] == "sid=a"
    assert captured["request_spec"] == '{"method":"POST"}'
    assert captured["oracle_spec"] == '{"url":"https://target.test/state"}'
    assert captured["reset_spec"] == '{"url":"https://target.test/reset"}'
    assert captured["copies"] == 7
    assert captured["rounds"] == 4
