import pytest

from core.evidence.execution_anchor import ExecutionAnchorEngine, SpeculationLanguageFilter, UnexecutedClaimBlocker


@pytest.mark.parametrize("word", ["\u53ef\u80fd", "\u4e5f\u8bb8", "\u4f3c\u4e4e", "\u770b\u8d77\u6765", "\u6211\u8ba4\u4e3a", "\u7591\u4f3c", "probably", "might be", "may be", "likely", "seems"])
def test_speculation_filter(word):
    filter_ = SpeculationLanguageFilter()
    assert filter_.should_block(f"{word} \u5b58\u5728 SQLi")
    assert not filter_.should_block(f"{word}\u9700\u8981\u7ee7\u7eed\u6d4b\u8bd5")


@pytest.mark.parametrize("claim", ["SQLi", "XSS", "RCE", "SSRF", "IDOR", "LFI", "CSRF", "XXE", "\u6f0f\u6d1e\u5b58\u5728", "\u53d1\u73b0\u6f0f\u6d1e", "\u786e\u8ba4\u6f0f\u6d1e"])
def test_all_technical_claims_are_detected(claim):
    assert SpeculationLanguageFilter().should_block(f"\u53ef\u80fd {claim}")


@pytest.mark.parametrize("evidence", ["[200/431B]", "HTTP/1.1 200 OK", "curl -i https://example.test", "wget https://example.test", "httpx -u https://example.test", "requests.get('https://example.test')", "requests.post(url, data=payload)", "STATUS: 200\nPAYLOAD: proof"])
def test_execution_evidence_is_accepted(evidence):
    assert not UnexecutedClaimBlocker().should_block(f"\u786e\u8ba4\u5b58\u5728 XSS\n{evidence}")


def test_unexecuted_claim_is_blocked():
    blocker = UnexecutedClaimBlocker()
    assert blocker.should_block("\u786e\u8ba4\u5b58\u5728 SSRF")
    assert not blocker.should_block("\u5efa\u8bae\u7ee7\u7eed\u68c0\u67e5 SSRF \u53c2\u6570")


def test_engine_runs_a_then_b_and_counts_blocks():
    engine = ExecutionAnchorEngine()
    first = engine.process("\u53ef\u80fd\u5b58\u5728 SQLi")
    second = engine.process("\u786e\u8ba4\u5b58\u5728 IDOR")
    third = engine.process("\u786e\u8ba4\u5b58\u5728 RCE\nHTTP/1.1 200 OK")
    assert first["blocker"] == "speculation_language" and first["blocked_count"] == 1
    assert second["blocker"] == "unexecuted_claim" and second["blocked_count"] == 2
    assert third == {"blocked": False, "blocker": None, "inject_message": "", "blocked_count": 2}