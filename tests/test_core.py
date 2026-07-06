"""
Hunter v7 核心模块测试
"""

import pytest
import asyncio
from pathlib import Path
from core.result import Result, ok, err
from core.vuln_classification import VulnClassification
from core.vuln_finding import VulnFinding, SubmissionTier, ProofStrength
from core.poc_verifier import PoCVerifier
from core.report_filter import ReportFilter
from core.phases import PhaseName, PHASES
from core.audit import AuditSession


class TestResult:
    def test_ok(self):
        r = ok(42)
        assert r.ok
        assert r.value == 42
        assert r.error is None

    def test_err(self):
        r = err("fail")
        assert not r.ok
        assert r.error == "fail"
        assert r.value is None

    def test_unwrap_ok(self):
        r = ok("hello")
        assert r.unwrap() == "hello"

    def test_unwrap_err(self):
        r = err("fail")
        with pytest.raises(RuntimeError):
            r.unwrap()

    def test_map_ok(self):
        r = ok(5)
        mapped = r.map(lambda x: x * 2)
        assert mapped.ok
        assert mapped.value == 10

    def test_map_err(self):
        r = err("fail")
        mapped = r.map(lambda x: x * 2)
        assert not mapped.ok
        assert mapped.error == "fail"


class TestVulnClassification:
    def test_exploited_in_report(self):
        assert VulnClassification.EXPLOITED.include_in_report

    def test_potential_not_in_report(self):
        assert not VulnClassification.POTENTIAL.include_in_report

    def test_false_positive_not_in_report(self):
        assert not VulnClassification.FALSE_POSITIVE.include_in_report

    def test_reportable_and_strong_in_report(self):
        assert VulnClassification.REPORTABLE.include_in_report
        assert VulnClassification.STRONG.include_in_report
        assert not VulnClassification.LEAD.include_in_report


class TestVulnFinding:
    def test_creation(self):
        f = VulnFinding(
            id="test-1",
            title="Test Vuln",
            description="Test desc",
            severity="high",
            vuln_type="sqli",
            url="http://example.com",
        )
        assert f.id == "test-1"
        assert f.severity == "high"
        assert not f.exploited
        assert f.submission_tier == SubmissionTier.LEAD
        assert not f.reportable
        assert f.proof_strength == ProofStrength.NONE

    def test_exploited(self):
        f = VulnFinding(
            id="test-2",
            title="Test Vuln",
            description="Test desc",
            severity="critical",
            vuln_type="rce",
            url="http://example.com",
            classification=VulnClassification.EXPLOITED,
            exploited=True,
            exploitation_success=True,
        )
        assert f.exploited
        assert f.classification == VulnClassification.EXPLOITED
        assert f.submission_tier == SubmissionTier.LEAD


class TestPhases:
    def test_phase_count(self):
        assert len(PHASES) == 5

    def test_pre_recon_agents(self):
        phase = PHASES[PhaseName.PRE_RECON]
        assert "subdomain" in phase.agents
        assert "port-scan" in phase.agents
        assert "tech-detect" in phase.agents
        assert "dns-info" in phase.agents
        assert "js-analyze" in phase.agents

    def test_recon_agents(self):
        phase = PHASES[PhaseName.RECON]
        assert "dir-enum" in phase.agents
        assert "api-discover" in phase.agents
        assert "param-discover" in phase.agents
        assert "auth-analysis" in phase.agents
        assert "endpoint-map" in phase.agents

    def test_vuln_analysis_agents(self):
        phase = PHASES[PhaseName.VULN_ANALYSIS]
        assert len(phase.agents) == 13
        assert "sqli-vuln" in phase.agents
        assert "xss-vuln" in phase.agents
        assert "ssrf-vuln" in phase.agents

    def test_exploitation_agents(self):
        phase = PHASES[PhaseName.EXPLOITATION]
        assert len(phase.agents) == 12
        assert "sqli-exploit" in phase.agents
        assert "chain-exploit" in phase.agents

    def test_reporting_agents(self):
        phase = PHASES[PhaseName.REPORTING]
        assert len(phase.agents) == 4
        assert not phase.parallel


class TestReportFilter:
    def test_filter_exploited(self):
        f = ReportFilter()
        findings = [
            VulnFinding(id="1", title="A", description="", severity="high", vuln_type="sqli", url="",
                        classification=VulnClassification.EXPLOITED, classification_reason="test", exploited=True),
            VulnFinding(id="2", title="B", description="", severity="medium", vuln_type="xss", url="",
                        classification=VulnClassification.POTENTIAL, classification_reason="test"),
            VulnFinding(id="3", title="C", description="", severity="low", vuln_type="info-leak", url="",
                        classification=VulnClassification.FALSE_POSITIVE, classification_reason="test"),
        ]
        result = f.filter_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"

    def test_statistics(self):
        f = ReportFilter()
        findings = [
            VulnFinding(id="1", title="A", description="", severity="high", vuln_type="sqli", url="",
                        classification=VulnClassification.EXPLOITED, classification_reason="test", exploited=True),
            VulnFinding(id="2", title="B", description="", severity="medium", vuln_type="xss", url="",
                        classification=VulnClassification.POTENTIAL, classification_reason="test"),
        ]
        f.filter_findings(findings)
        stats = f.get_statistics()
        assert stats['exploited'] == 1
        assert stats['potential'] == 1

    def test_generate_submission_report_omits_leads(self):
        report_filter = ReportFilter()
        findings = [
            VulnFinding(
                id="1",
                title="学生可越权访问他人成绩详情",
                description="可访问他人成绩详情",
                severity="high",
                vuln_type="idor",
                url="https://example.com/score/2",
                classification=VulnClassification.STRONG,
                classification_reason="获取到他人真实数据",
                submission_tier=SubmissionTier.STRONG,
                reportable=True,
                business_impact="低权限用户可查看他人成绩数据",
                impact_scope="任意学生对象",
                proof_strength=ProofStrength.STRONG,
                remediation="校验资源归属",
            ),
            VulnFinding(
                id="2",
                title="公开 JS 文件包含接口路径",
                description="普通前端接口线索",
                severity="info",
                vuln_type="info-leak",
                url="https://example.com/app.js",
                classification=VulnClassification.LEAD,
                classification_reason="仅线索，不构成正式漏洞",
                submission_tier=SubmissionTier.LEAD,
                reportable=False,
                lead_reason="公开 JS 端点默认仅进线索池",
            ),
        ]
        report_filter.filter_findings(findings)
        markdown = report_filter.generate_submission_report(target="https://example.com")
        assert "学生可越权访问他人成绩详情" in markdown
        assert "公开 JS 文件包含接口路径" not in markdown
        assert "漏洞概述" in markdown

    def test_generate_hackerone_report_contains_official_sections(self):
        report_filter = ReportFilter()
        findings = [
            VulnFinding(
                id="1",
                title="Student can access another student's grade detail",
                description="The endpoint returns another student's grade detail",
                severity="high",
                vuln_type="idor",
                url="https://example.com/score/2",
                classification=VulnClassification.STRONG,
                classification_reason="Access to another user's real data",
                submission_tier=SubmissionTier.STRONG,
                reportable=True,
                business_impact="A low-privileged student can access another student's grade information.",
                impact_scope="Any student object",
                proof_strength=ProofStrength.STRONG,
                request="GET /score/2",
                response='{\"grade\":\"95\"}',
            ),
        ]
        report_filter.filter_findings(findings)
        markdown = report_filter.generate_submission_report(target="https://example.com", style="hackerone")
        assert "Summary" in markdown
        assert "Steps to reproduce" in markdown
        assert "Impact" in markdown
        assert "Supporting material" in markdown

    def test_appendix_includes_evidence_file_paths(self):
        report_filter = ReportFilter()
        findings = [
            VulnFinding(
                id="1",
                title="Student can access another student's grade detail",
                description="The endpoint returns another student's grade detail",
                severity="high",
                vuln_type="idor",
                url="https://example.com/score/2",
                classification=VulnClassification.STRONG,
                classification_reason="Access to another user's real data",
                submission_tier=SubmissionTier.STRONG,
                reportable=True,
                business_impact="A low-privileged student can access another student's grade information.",
                impact_scope="Any student object",
                proof_strength=ProofStrength.STRONG,
                request="GET /score/2",
                response="{\"grade\":\"95\"}",
                request_file="D:/Hunter/evidence/request.txt",
                response_file="D:/Hunter/evidence/response.txt",
                screenshot_files=["D:/Hunter/evidence/screen1.png"],
                evidence_files=["D:/Hunter/evidence/raw.json"],
            ),
        ]
        report_filter.filter_findings(findings)
        markdown = report_filter.generate_submission_report(target="https://example.com", style="hackerone")
        assert "Request file: D:/Hunter/evidence/request.txt" in markdown
        assert "Response file: D:/Hunter/evidence/response.txt" in markdown
        assert "Screenshot: D:/Hunter/evidence/screen1.png" in markdown
        assert "Evidence file: D:/Hunter/evidence/raw.json" in markdown

    def test_generate_butian_report_contains_cn_sections(self):
        report_filter = ReportFilter()
        findings = [
            VulnFinding(
                id="1",
                title="?????????????",
                description="?????????",
                severity="high",
                vuln_type="idor",
                url="https://example.com/score/2",
                classification=VulnClassification.STRONG,
                classification_reason="?????????",
                submission_tier=SubmissionTier.STRONG,
                reportable=True,
                business_impact="??????????????",
                impact_scope="??????",
                proof_strength=ProofStrength.STRONG,
                request="GET /score/2",
                response="{\"grade\":\"95\"}",
            ),
        ]
        report_filter.filter_findings(findings)
        markdown = report_filter.generate_submission_report(target="https://example.com", style="butian")
        assert "????" in markdown
        assert "????" in markdown
        assert "????" in markdown
        assert "????" in markdown

    def test_generate_vulbox_report_contains_cn_sections(self):
        report_filter = ReportFilter()
        findings = [
            VulnFinding(
                id="1",
                title="?????????????",
                description="?????????",
                severity="high",
                vuln_type="idor",
                url="https://example.com/score/2",
                classification=VulnClassification.STRONG,
                classification_reason="?????????",
                submission_tier=SubmissionTier.STRONG,
                reportable=True,
                business_impact="??????????????",
                impact_scope="??????",
                proof_strength=ProofStrength.STRONG,
                request="GET /score/2",
                response="{\"grade\":\"95\"}",
            ),
        ]
        report_filter.filter_findings(findings)
        markdown = report_filter.generate_submission_report(target="https://example.com", style="vulbox")
        assert "????" in markdown
        assert "????" in markdown
        assert "????" in markdown
        assert "????" in markdown


class StubHttpClient:
    def __init__(self, response):
        self.response = response

    async def send(self, url, method="GET", param=None, payload=None):
        return self.response


class TestStrictSrcVerifier:
    @pytest.mark.asyncio
    async def test_xss_reflection_without_execution_stays_lead(self):
        verifier = PoCVerifier(
            http_client=StubHttpClient({
                "text": "<div><script>alert(1)</script></div>",
                "status": 200,
                "headers": {},
            })
        )
        finding = VulnFinding(
            id="xss-1",
            title="XSS",
            description="payload reflected",
            severity="medium",
            vuln_type="xss",
            url="https://example.com/search",
            payload="<script>alert(1)</script>",
        )
        verified = await verifier.verify(finding)
        assert verified.submission_tier == SubmissionTier.LEAD
        assert not verified.reportable
        assert verified.proof_strength == ProofStrength.WEAK

    @pytest.mark.asyncio
    async def test_idor_sensitive_data_becomes_strong(self):
        verifier = PoCVerifier(
            http_client=StubHttpClient({
                "text": '{"email":"victim@example.com","token":"secret-token"}',
                "status": 200,
                "headers": {},
            })
        )
        finding = VulnFinding(
            id="idor-1",
            title="IDOR",
            description="can access another user record",
            severity="high",
            vuln_type="idor",
            url="https://example.com/api/user/2",
            payload="2",
        )
        verified = await verifier.verify(finding)
        assert verified.submission_tier == SubmissionTier.STRONG
        assert verified.reportable
        assert verified.proof_strength == ProofStrength.STRONG
        assert "他人" in verified.business_impact


class TestAuditSessionReportExports:
    def test_export_report_json_separates_reportable_and_leads(self):
        session = AuditSession(session_id="src-session", target="https://example.com")
        session.set_report_data(
            reportable_findings=[
                {
                    "id": "1",
                    "title": "学生可越权访问他人成绩详情",
                    "submission_tier": "strong",
                    "reportable": True,
                }
            ],
            lead_findings=[
                {
                    "id": "2",
                    "title": "公开 JS 文件包含接口路径",
                    "submission_tier": "lead",
                    "reportable": False,
                }
            ],
            summary={"reportable_count": 1, "lead_count": 1},
        )
        report_json = session.export_report_json()
        assert report_json["reportable_findings"][0]["title"] == "学生可越权访问他人成绩详情"
        assert report_json["lead_findings"][0]["title"] == "公开 JS 文件包含接口路径"


class TestEvidenceAttachmentDiscovery:
    def test_result_to_report_item_maps_output_files(self):
        import mcp_server

        item = mcp_server._result_to_report_item({
            "agent": "idor-vuln",
            "display_name": "IDOR Vulnerability Agent",
            "submission_tier": "strong",
            "reportable": True,
            "proof_strength": "strong",
            "output_files": [
                "D:/Hunter/evidence/request.txt",
                "D:/Hunter/evidence/response.txt",
                "D:/Hunter/evidence/screenshot-1.png",
                "D:/Hunter/evidence/raw.json",
            ],
        })
        assert item["request_file"] == "D:/Hunter/evidence/request.txt"
        assert item["response_file"] == "D:/Hunter/evidence/response.txt"
        assert "D:/Hunter/evidence/screenshot-1.png" in item["screenshot_files"]
        assert "D:/Hunter/evidence/raw.json" in item["evidence_files"]

    def test_discover_evidence_files_from_directory(self, tmp_path: Path):
        import mcp_server

        evidence_dir = tmp_path / "tool_output"
        evidence_dir.mkdir()
        files = [
            evidence_dir / "example_com_idor-vuln_request.txt",
            evidence_dir / "example_com_idor-vuln_response.txt",
            evidence_dir / "example_com_idor-vuln_screenshot.png",
            evidence_dir / "example_com_idor-vuln_result.json",
        ]
        for file in files:
            file.write_text("x", encoding="utf-8")

        discovered = mcp_server._discover_evidence_attachments(
            agent_name="idor-vuln",
            target="https://example.com",
            evidence_dir=evidence_dir,
        )
        assert discovered["request_file"].endswith("request.txt")
        assert discovered["response_file"].endswith("response.txt")
        assert any(path.endswith("screenshot.png") for path in discovered["screenshot_files"])
        assert any(path.endswith("result.json") for path in discovered["evidence_files"])
