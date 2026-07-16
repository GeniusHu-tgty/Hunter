from core.evidence.verdict_engine import Evidence, Verdict, VerdictEngine, VulnType


def evidence(body="", *, baseline_body="", payload="test", status_code=200,
             baseline_status=200, reproduction_count=3, metadata=None):
    return Evidence(
        request={"method": "GET", "url": "https://target.test", "headers": {}, "body": ""},
        response={"status_code": status_code, "headers": {}, "body": body},
        baseline_response={"status_code": baseline_status, "headers": {}, "body": baseline_body},
        payload=payload,
        reproduction_count=reproduction_count,
        metadata=metadata or {},
    )


def test_sqli_new_database_error_is_verified():
    result = VerdictEngine().assess(
        VulnType.SQLI,
        evidence("You have an SQL syntax error near 'x'", baseline_body="normal page", payload="'"),
    )
    assert result.verdict is Verdict.VERIFIED
    assert "database_error" in result.matched_signals


def test_sqli_baseline_database_error_is_refuted():
    text = "Microsoft SQL Server error"
    result = VerdictEngine().assess(VulnType.SQLI, evidence(text, baseline_body=text, payload="'"))
    assert result.verdict is Verdict.REFUTED


def test_sqli_union_growth_and_structured_data_is_verified():
    result = VerdictEngine().assess(
        VulnType.SQLI,
        evidence('{"users":[{"id":1,"username":"admin"}]}', baseline_body="ok", payload="' UNION SELECT 1--"),
    )
    assert result.verdict is Verdict.VERIFIED
    assert "union_structured_data" in result.matched_signals


def test_sqli_timing_requires_fast_baseline():
    result = VerdictEngine().assess(
        VulnType.SQLI,
        evidence("ok", metadata={"response_time": 5.4, "baseline_response_time": 0.4}),
    )
    assert result.verdict is Verdict.VERIFIED
    assert "timing_delta" in result.matched_signals


def test_strong_signal_with_too_few_reproductions_is_likely():
    result = VerdictEngine().assess(VulnType.LFI, evidence("root:x:0:0:root:/root:/bin/bash", reproduction_count=1))
    assert result.verdict is Verdict.LIKELY


def test_xss_raw_payload_in_html_text_is_verified():
    payload = "<script>alert(1)</script>"
    result = VerdictEngine().assess(VulnType.XSS, evidence(f"<html><body>{payload}</body></html>", payload=payload))
    assert result.verdict is Verdict.VERIFIED


def test_xss_html_encoded_payload_is_refuted():
    payload = "<script>alert(1)</script>"
    result = VerdictEngine().assess(VulnType.XSS, evidence("&lt;script&gt;alert(1)&lt;/script&gt;", payload=payload))
    assert result.verdict is Verdict.REFUTED


def test_xss_payload_inside_comment_is_refuted():
    payload = "<script>alert(1)</script>"
    result = VerdictEngine().assess(VulnType.XSS, evidence(f"<!-- {payload} -->", payload=payload))
    assert result.verdict is Verdict.REFUTED


def test_xss_payload_inside_attribute_without_breakout_is_refuted():
    payload = "alert(1)"
    result = VerdictEngine().assess(VulnType.XSS, evidence(f'<input value="{payload}">', payload=payload))
    assert result.verdict is Verdict.REFUTED


def test_xss_attribute_breakout_payload_is_verified():
    payload = '"><script>alert(1)</script>'
    result = VerdictEngine().assess(VulnType.XSS, evidence(f'<input value="{payload}">', payload=payload))
    assert result.verdict is Verdict.VERIFIED


def test_xss_case_changed_executable_variant_is_verified():
    payload = "<script>alert(1)</script>"
    result = VerdictEngine().assess(VulnType.XSS, evidence("<ScRiPt>alert(1)</sCrIpT>", payload=payload))
    assert result.verdict is Verdict.VERIFIED
    assert "browser_executable_variant" in result.matched_signals


def test_ssrf_collaborator_callback_is_verified():
    result = VerdictEngine().assess(
        VulnType.SSRF,
        evidence("queued", metadata={"collaborator_callbacks": [{"protocol": "dns"}]}),
    )
    assert result.verdict is Verdict.VERIFIED


def test_ssrf_metadata_and_internal_service_fingerprints_are_verified():
    engine = VerdictEngine()
    metadata_result = engine.assess(
        VulnType.SSRF,
        evidence("security-credentials/", payload="http://169.254.169.254/latest/meta-data/"),
    )
    redis_result = engine.assess(VulnType.SSRF, evidence("-NOAUTH Authentication required"))
    assert metadata_result.verdict is Verdict.VERIFIED
    assert redis_result.verdict is Verdict.VERIFIED


def test_lfi_os_and_php_source_signatures_are_verified():
    engine = VerdictEngine()
    assert engine.assess(VulnType.LFI, evidence("daemon:x:1:1:")).verdict is Verdict.VERIFIED
    assert engine.assess(VulnType.LFI, evidence("<?php define('DB_HOST', 'x');")).verdict is Verdict.VERIFIED


def test_rce_unique_echo_marker_and_command_output_are_verified():
    marker = "HUNTER_a81f9c"
    engine = VerdictEngine()
    echo_result = engine.assess(
        VulnType.RCE,
        evidence(f"result={marker}", payload=f"echo {marker}", metadata={"command": "echo", "unique_marker": marker}),
    )
    id_result = engine.assess(
        VulnType.RCE,
        evidence("uid=1000(app) gid=1000(app)", payload=";id", metadata={"command": "id"}),
    )
    assert echo_result.verdict is Verdict.VERIFIED
    assert id_result.verdict is Verdict.VERIFIED


def test_auth_bypass_redirect_and_authenticated_marker_are_verified():
    result = VerdictEngine().assess(
        VulnType.AUTH_BYPASS,
        evidence("Welcome <a href='/logout'>logout</a>", status_code=302, metadata={"redirect_location": "/dashboard"}),
    )
    assert result.verdict is Verdict.VERIFIED


def test_idor_requires_cross_user_data_proof():
    verified = VerdictEngine().assess(
        VulnType.IDOR,
        evidence('{"user_id":"user-b","email":"b@example.test"}', metadata={
            "request_user": "user-a", "resource_owner": "user-b", "owner_data_returned": True,
        }),
    )
    inconclusive = VerdictEngine().assess(VulnType.IDOR, evidence("different length"))
    assert verified.verdict is Verdict.VERIFIED
    assert inconclusive.verdict is Verdict.INCONCLUSIVE


def test_race_requires_normal_control_stable_oracle_and_verified_gate():
    strong = evidence(
        metadata={
            "control_normal": True,
            "invariant_violated": True,
            "oracle_stable": True,
            "gate_verified": True,
        },
        reproduction_count=3,
    )
    weak = evidence(
        metadata={
            "control_normal": False,
            "invariant_violated": True,
            "oracle_stable": True,
            "gate_verified": True,
        },
        reproduction_count=3,
    )

    assert VerdictEngine().assess(VulnType.RACE, strong).verdict is Verdict.VERIFIED
    assert VerdictEngine().assess(VulnType.RACE, weak).verdict is Verdict.REFUTED


def test_upload_requires_executable_upload_and_reachable_non_404_url():
    result = VerdictEngine().assess(
        VulnType.UPLOAD,
        evidence("HUNTER_UPLOAD_MARKER", metadata={
            "uploaded_executable": True,
            "uploaded_file_status": 200,
            "uploaded_file_url": "https://target.test/uploads/probe.php",
        }),
    )
    assert result.verdict is Verdict.VERIFIED


def test_remaining_vulnerability_types_have_programmatic_rules():
    engine = VerdictEngine()
    cases = [
        (VulnType.OPEN_REDIRECT, evidence("", status_code=302, metadata={"redirect_location": "https://attacker.test/x", "payload_host": "attacker.test"})),
        (VulnType.CSRF, evidence("changed", metadata={"state_changed": True, "csrf_protection_missing": True})),
        (VulnType.XXE, evidence("root:x:0:0:", payload="<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>")),
        (VulnType.SSTI, evidence("result=49", payload="{{7*7}}", metadata={"expected_template_result": "49"})),
        (VulnType.INFO_DISCLOSURE, evidence("-----BEGIN PRIVATE KEY-----")),
    ]
    for vuln_type, item in cases:
        assert engine.assess(vuln_type, item).verdict is Verdict.VERIFIED


def test_evidence_accepts_mapping_and_result_is_serializable():
    result = VerdictEngine().assess(
        VulnType.LFI,
        {
            "request": {"method": "GET", "url": "https://target.test", "headers": {}, "body": ""},
            "response": {"status_code": 200, "headers": {}, "body": "[drivers]"},
            "baseline_response": {"status_code": 200, "headers": {}, "body": "normal"},
            "payload": "../../windows/win.ini",
            "reproduction_count": 3,
        },
    )
    assert result.to_dict()["verdict"] == "verified"
    assert result.to_dict()["vuln_type"] == "lfi"


def test_xss_javascript_url_in_plain_text_is_refuted():
    result = VerdictEngine().assess(VulnType.XSS, evidence("Search: javascript:alert(1)", payload="javascript:alert(1)"))
    assert result.verdict is Verdict.REFUTED


def test_ssrf_fingerprint_already_in_baseline_is_refuted():
    result = VerdictEngine().assess(VulnType.SSRF, evidence("-NOAUTH Authentication required", baseline_body="-NOAUTH Authentication required"))
    assert result.verdict is Verdict.REFUTED


def test_auth_bypass_error_redirect_is_refuted():
    result = VerdictEngine().assess(VulnType.AUTH_BYPASS, evidence("", status_code=302, metadata={"redirect_location": "/error"}))
    assert result.verdict is Verdict.REFUTED


def test_open_redirect_same_origin_is_refuted():
    result = VerdictEngine().assess(
        VulnType.OPEN_REDIRECT,
        evidence("", status_code=302, payload="https://target.test/next", metadata={
            "redirect_location": "https://target.test/next", "payload_host": "target.test",
        }),
    )
    assert result.verdict is Verdict.REFUTED


def test_upload_server_error_is_refuted():
    result = VerdictEngine().assess(VulnType.UPLOAD, evidence("error", metadata={
        "uploaded_executable": True, "uploaded_file_status": 500,
        "uploaded_file_url": "https://target.test/uploads/probe.php",
    }))
    assert result.verdict is Verdict.REFUTED


def test_rce_structured_output_requires_new_output_and_matching_command():
    result = VerdictEngine().assess(
        VulnType.RCE,
        evidence("Linux host 6.1.0", baseline_body="Linux host 6.1.0", payload="noop", metadata={"command": "noop"}),
    )
    assert result.verdict is Verdict.REFUTED


def test_xss_case_variant_inside_inert_context_is_refuted():
    payload = "<script>alert(1)</script>"
    engine = VerdictEngine()
    for body in (
        "<!-- <ScRiPt>alert(1)</sCrIpT> -->",
        "<textarea><ScRiPt>alert(1)</sCrIpT></textarea>",
        "<xmp><ScRiPt>alert(1)</sCrIpT></xmp>",
    ):
        assert engine.assess(VulnType.XSS, evidence(body, payload=payload)).verdict is Verdict.REFUTED


def test_sqli_union_growth_requires_new_structured_shape():
    result = VerdictEngine().assess(
        VulnType.SQLI,
        evidence(
            '{"users":[{"id":1},{"id":2},{"id":3}]}',
            baseline_body='{"users":[{"id":1}]}',
            payload="' UNION SELECT 1--",
        ),
    )
    assert result.verdict is Verdict.REFUTED


def test_ssrf_cloud_metadata_fingerprint_already_in_baseline_is_refuted():
    result = VerdictEngine().assess(
        VulnType.SSRF,
        evidence("ami-id", baseline_body="ami-id", payload="http://169.254.169.254/latest/meta-data/"),
    )
    assert result.verdict is Verdict.REFUTED
