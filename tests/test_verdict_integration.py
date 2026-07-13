import asyncio
import json

import mcp_server


def run_async(coro):
    return asyncio.run(coro)


def test_auto_tool_attaches_verdict_from_scanner_evidence(monkeypatch):
    import core.auto_xss as auto_xss

    payload = "<script>alert(1)</script>"
    monkeypatch.setattr(auto_xss, "auto_xss_impl", lambda *args, **kwargs: {
        "vulnerable": True,
        "evidence": {
            "request": {"method": "GET", "url": "https://t/?q=x", "headers": {}, "body": ""},
            "response": {"status_code": 200, "headers": {}, "body": f"<body>{payload}</body>"},
            "baseline_response": {"status_code": 200, "headers": {}, "body": "<body></body>"},
            "payload": payload,
            "reproduction_count": 3,
        },
    })
    result = json.loads(run_async(mcp_server.hunter_auto_xss("https://t", "q", "GET")))
    assert result["verdict"]["verdict"] == "verified"
    assert result["vulnerable"] is True


def test_auto_tool_does_not_confirm_legacy_boolean_without_evidence(monkeypatch):
    import core.auto_sqli as auto_sqli

    monkeypatch.setattr(auto_sqli, "auto_sqli_impl", lambda *args, **kwargs: {"vulnerable": True})
    result = json.loads(run_async(mcp_server.hunter_auto_sqli("https://t", "id", "GET")))
    assert result["legacy_vulnerable"] is True
    assert result["vulnerable"] is False
    assert result["verdict"]["verdict"] == "inconclusive"


def test_auto_tool_preserves_unrelated_scanner_results(monkeypatch):
    import core.auto_sqli as auto_sqli

    monkeypatch.setattr(auto_sqli, "auto_sqli_impl", lambda *args, **kwargs: {"scanner": "sqli", "target": "https://t"})
    result = json.loads(run_async(mcp_server.hunter_auto_sqli("https://t")))
    assert result["scanner"] == "sqli"
    assert result["target"] == "https://t"
    assert result["verdict"]["verdict"] == "inconclusive"


def test_xss_scanner_emits_standard_evidence_and_refutes_encoded_reflection():
    from core.auto_xss import AutoXSS
    from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

    class Response:
        status_code = 200
        headers = {}
        text = "&lt;script&gt;alert(1)&lt;/script&gt;"

    class Session:
        def get(self, *args, **kwargs):
            return Response()

    scanner = AutoXSS("https://t", session=Session())
    scanner.baseline_response = {"status": 200, "headers": {}, "body": "normal", "length": 6}
    probe = scanner._test_payload("<script>alert(1)</script>")
    item = scanner._build_evidence("<script>alert(1)</script>", probe, 3)
    assert VerdictEngine().assess(VulnType.XSS, item).verdict is Verdict.REFUTED


def test_sqli_scanner_builds_evidence_with_baseline_and_timing():
    from core.auto_sqli import AutoSQLi
    from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

    scanner = AutoSQLi("https://t", session=object())
    scanner.baseline_response = {"status": 200, "headers": {}, "body": "normal", "length": 6, "time": 0.2}
    probe = {"status": 500, "headers": {}, "body": "SQL syntax error 1064", "length": 21, "time": 0.4}
    item = scanner._build_evidence("'", probe, 3)
    result = VerdictEngine().assess(VulnType.SQLI, item)
    assert result.verdict is Verdict.VERIFIED
    assert item["metadata"]["baseline_response_time"] == 0.2


def test_ssrf_scanner_builds_evidence_for_internal_fingerprint():
    from core.auto_ssrf import AutoSSRF
    from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

    scanner = AutoSSRF("https://t", session=object())
    scanner.baseline_response = {"status": 200, "headers": {}, "body": "normal", "length": 6}
    probe = {"status": 200, "headers": {}, "body": "-NOAUTH Authentication required", "length": 31}
    item = scanner._build_evidence("http://127.0.0.1:6379", probe, 3)
    assert VerdictEngine().assess(VulnType.SSRF, item).verdict is Verdict.VERIFIED


def test_cmd_scanner_builds_evidence_for_identity_output():
    from core.auto_cmd import AutoCMD
    from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

    scanner = AutoCMD("https://t", session=object())
    scanner.baseline_response = {"status": 200, "headers": {}, "body": "pong", "length": 4, "time": 0.1}
    probe = {"status": 200, "headers": {}, "body": "uid=1000(app) gid=1000(app)", "length": 29, "time": 0.1}
    item = scanner._build_evidence("127.0.0.1;id", probe, 3)
    assert VerdictEngine().assess(VulnType.RCE, item).verdict is Verdict.VERIFIED


def test_ssti_scanner_builds_expression_evidence():
    from core.auto_ssti import AutoSSTI
    from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

    scanner = AutoSSTI("https://t", session=object())
    scanner.baseline_response = {"status": 200, "headers": {}, "body": "normal"}
    probe = {"status": 200, "headers": {}, "body": "result=49"}
    item = scanner._build_evidence("{{7*7}}", probe, "49", 3)
    assert VerdictEngine().assess(VulnType.SSTI, item).verdict is Verdict.VERIFIED


def test_xxe_scanner_builds_file_disclosure_evidence():
    from core.auto_xxe import AutoXXE
    from core.evidence.verdict_engine import Verdict, VerdictEngine, VulnType

    scanner = AutoXXE("https://t", session=object())
    scanner.baseline_response = {"status": 200, "headers": {}, "body": "normal"}
    payload = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    probe = {"status": 200, "headers": {}, "body": "root:x:0:0:root:/root:/bin/bash"}
    item = scanner._build_evidence(payload, probe, 3)
    assert VerdictEngine().assess(VulnType.XXE, item).verdict is Verdict.VERIFIED
