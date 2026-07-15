import json

from core.evidence.normalizer import EvidenceNormalizer
from core.evidence.verdict_engine import (
    Verdict,
    VerdictEngine,
    VulnType,
)
from core.unified_scanner import UnifiedOrchestrationBridge
from core.workflow.kernel import UnifiedOrchestrator, WorkflowKernel


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


def workflow(kernel, slug="evidence-case"):
    kernel.create(
        slug,
        "evidence binding test",
        inputs=[{"type": "url", "value": "https://example.test"}],
        mode="autopilot",
        success_conditions=["confirmed-finding"],
        proof_types=["request-response"],
    )
    return slug


def append_confirmation(kernel, slug, findings):
    kernel._append(
        slug,
        "orchestrator.stage.completed",
        {
            "stage": "vulnerability_confirmation",
            "status": "completed",
            "result": {"findings": findings},
        },
    )


def test_finding_binds_only_its_verdict_specific_evidence(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = workflow(kernel)
    append_confirmation(
        kernel,
        slug,
        [
            {
                "title": "Verified sqli",
                "type": "sqli",
                "status": "confirmed",
                "verdict": "verified",
                "verdict_id": "verdict-act-sqli",
                "evidence_keys": ["evidence-act-sqli"],
                "proof_type": "verdict-engine",
            }
        ],
    )
    orchestrator = UnifiedOrchestrator(kernel)

    orchestrator._register_evidence_and_findings(
        slug,
        {
            "evidence": [
                {
                    "evidence_key": "evidence-act-sqli",
                    "summary": "SQLi differential",
                    "source": "hunter_auto_sqli",
                    "type": "proof-attempt",
                },
                {
                    "evidence_key": "evidence-act-xss",
                    "summary": "Unrelated XSS observation",
                    "source": "hunter_auto_xss",
                    "type": "proof-attempt",
                },
            ]
        },
    )

    state = kernel.materialize(slug)
    evidence_by_summary = {
        item["summary"]: item["id"] for item in state["evidence"]
    }
    assert state["findings"][0]["evidence_ids"] == [
        evidence_by_summary["SQLi differential"]
    ]
    assert (
        evidence_by_summary["Unrelated XSS observation"]
        not in state["findings"][0]["evidence_ids"]
    )
    assert all(
        item["type"] != "pattern-confirmation"
        for item in state["evidence"]
    )


def test_verified_finding_without_matching_evidence_is_not_promoted(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = workflow(kernel)
    append_confirmation(
        kernel,
        slug,
        [
            {
                "title": "Verified sqli",
                "type": "sqli",
                "status": "confirmed",
                "verdict": "verified",
                "verdict_id": "verdict-act-sqli",
                "evidence_keys": ["missing-evidence"],
            }
        ],
    )

    UnifiedOrchestrator(kernel)._register_evidence_and_findings(
        slug,
        {"evidence": []},
    )

    state = kernel.materialize(slug)
    assert state["findings"] == []
    assert all(
        item["type"] != "pattern-confirmation"
        for item in state["evidence"]
    )


def test_evidence_learning_records_memory_from_verified_verdict():
    class TargetMemory:
        def __init__(self):
            self.attacks = []
            self.vulnerabilities = []

        def query_target(self, target):
            return {"fingerprints": {}}

        def record_target(self, *args, **kwargs):
            return {}

        def record_attack(self, target, **kwargs):
            self.attacks.append((target, kwargs))

        def record_vulnerability(self, target, **kwargs):
            self.vulnerabilities.append((target, kwargs))

    class TechniqueMemory:
        def __init__(self):
            self.attempts = []

        def record_attempt(self, **kwargs):
            self.attempts.append(kwargs)

    target_memory = TargetMemory()
    technique_memory = TechniqueMemory()
    bridge = UnifiedOrchestrationBridge(
        {
            "target_memory": target_memory,
            "technique_memory": technique_memory,
            "evidence_normalizer": EvidenceNormalizer(),
        }
    )
    attempt = nested_attempt(
        body="You have an error in your SQL syntax",
        baseline="normal",
        reproductions=3,
    )
    attempt.update(
        {
            "transport_success": True,
            "probe_executed": True,
            "signal_detected": True,
            "vulnerability_confirmed": False,
            "verdict": "inconclusive",
        }
    )
    context = {
        "target_url": "https://example.test",
        "target_profile": {"fingerprints": {}},
        "stage_results": {
            "attack_execution": {"attempts": [attempt], "handoffs": []},
            "vulnerability_confirmation": {
                "verdicts": [
                    {
                        "action_id": "act-sqli",
                        "verdict": "verified",
                        "verdict_id": "verdict-act-sqli",
                        "evidence_key": "evidence-act-sqli",
                    }
                ],
                "findings": [
                    {
                        "type": "sqli",
                        "severity": "high",
                        "status": "confirmed",
                        "verdict": "verified",
                        "verdict_id": "verdict-act-sqli",
                        "evidence_keys": ["evidence-act-sqli"],
                    }
                ],
            },
        },
    }

    result = bridge.stage_evidence_learning(context)

    assert technique_memory.attempts[0]["vulnerability_confirmed"] is True
    assert technique_memory.attempts[0]["verdict"] == "verified"
    assert target_memory.attacks[0][1]["vulnerability_confirmed"] is True
    assert result["evidence"][0]["evidence_key"] == "evidence-act-sqli"


def test_report_projects_promoted_findings_and_evidence(tmp_path):
    kernel = WorkflowKernel(tmp_path)
    slug = workflow(kernel)
    append_confirmation(
        kernel,
        slug,
        [
            {
                "title": "Verified sqli",
                "type": "sqli",
                "status": "confirmed",
                "verdict": "verified",
                "verdict_id": "verdict-act-sqli",
                "evidence_keys": ["evidence-act-sqli"],
                "proof_type": "verdict-engine",
            }
        ],
    )
    orchestrator = UnifiedOrchestrator(kernel)
    orchestrator._register_evidence_and_findings(
        slug,
        {
            "evidence": [
                {
                    "evidence_key": "evidence-act-sqli",
                    "summary": "SQLi differential",
                    "source": "hunter_auto_sqli",
                    "type": "proof-attempt",
                }
            ]
        },
    )
    state = kernel.materialize(slug)

    result = orchestrator._stage_report(
        {
            "slug": slug,
            "workflow_id": state["workflow_id"],
            "target_url": "https://example.test",
            "attack_queue": [],
            "stage_results": {
                "vulnerability_confirmation": {"findings": []}
            },
        }
    )
    report = json.loads(
        open(result["report_path"], encoding="utf-8").read()
    )

    assert len(report["findings"]) == 1
    assert report["findings"][0]["verdict"] == "verified"
    assert report["findings"][0]["evidence"][0]["summary"] == (
        "SQLi differential"
    )
