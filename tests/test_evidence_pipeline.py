from core.evidence.normalizer import EvidenceNormalizer
from core.evidence.verdict_engine import (
    Verdict,
    VerdictEngine,
    VulnType,
)
from core.unified_scanner import UnifiedOrchestrationBridge


def nested_attempt(*, body, baseline, reproductions):
    return {
        "action_id": "act-sqli",
        "tool": "hunter_auto_sqli",
        "attack_surface": "sqli",
        "target": "https://example.test/?id=1",
        "response": {
            "status": "ok",
            "error": "tool metadata must not be response evidence",
            "data": {
                "evidence": {
                    "request": {
                        "url": "https://example.test/?id=1'"
                    },
                    "response": {
                        "status_code": 500,
                        "body": body,
                    },
                    "baseline_response": {
                        "status_code": 200,
                        "body": baseline,
                    },
                    "payload": "'",
                    "reproduction_count": reproductions,
                }
            },
        },
    }


def confirmation_bridge():
    return UnifiedOrchestrationBridge(
        {
            "evidence_normalizer": EvidenceNormalizer(),
            "verdict_engine": VerdictEngine(),
        }
    )


def confirmation_context(attempt):
    return {
        "target_url": "https://example.test",
        "stage_results": {
            "attack_execution": {
                "attempts": [attempt],
            }
        },
    }


def test_normalizer_reads_nested_auto_tool_evidence():
    vuln_type, evidence = EvidenceNormalizer().normalize_attempt(
        nested_attempt(
            body="You have an error in your SQL syntax",
            baseline="normal",
            reproductions=3,
        )
    )

    assert vuln_type is VulnType.SQLI
    assert evidence.response["status_code"] == 500
    assert evidence.baseline_response["body"] == "normal"
    assert evidence.metadata["action_id"] == "act-sqli"


def test_normalizer_never_treats_tool_error_text_as_response_body():
    _, evidence = EvidenceNormalizer().normalize_attempt(
        nested_attempt(
            body="normal",
            baseline="normal",
            reproductions=1,
        )
    )

    assert evidence.response["body"] == "normal"
    assert "tool metadata" not in evidence.response["body"]


def test_baseline_collision_is_refuted_even_after_three_reproductions():
    _, evidence = EvidenceNormalizer().normalize_attempt(
        nested_attempt(
            body="You have an error in your SQL syntax",
            baseline="You have an error in your SQL syntax",
            reproductions=3,
        )
    )

    result = VerdictEngine().assess(VulnType.SQLI, evidence)

    assert result.verdict is Verdict.REFUTED


def test_likely_verdict_does_not_create_confirmed_finding():
    result = confirmation_bridge().stage_confirmation(
        confirmation_context(
            nested_attempt(
                body="You have an error in your SQL syntax",
                baseline="normal",
                reproductions=1,
            )
        )
    )

    assert result["findings"] == []
    assert result["pending_review"][0]["verdict"] == "likely"


def test_verified_verdict_contains_action_and_evidence_identity():
    result = confirmation_bridge().stage_confirmation(
        confirmation_context(
            nested_attempt(
                body="You have an error in your SQL syntax",
                baseline="normal",
                reproductions=3,
            )
        )
    )

    finding = result["findings"][0]
    assert finding["verdict"] == "verified"
    assert finding["verdict_id"] == "verdict-act-sqli"
    assert finding["evidence_keys"] == ["evidence-act-sqli"]
