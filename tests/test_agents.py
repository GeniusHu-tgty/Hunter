"""
Hunter v7 Agent 测试
"""

import pytest
import asyncio
from core.audit import AuditSession
from core.vuln_finding import VulnFinding
from core.vuln_classification import VulnClassification
from agents.base import AgentInput, AgentOutput
from core.vuln_classification import VulnClassification


class TestAgentImports:
    """测试所有 Agent 能正确导入"""

    def test_pre_recon_agents(self):
        from agents.pre_recon.subdomain import SubdomainAgent
        from agents.pre_recon.port_scan import PortScanAgent
        from agents.pre_recon.tech_detect import TechDetectAgent
        from agents.pre_recon.dns_info import DnsInfoAgent
        from agents.pre_recon.js_analyze import JsAnalyzeAgent
        assert SubdomainAgent is not None

    def test_recon_agents(self):
        from agents.recon.dir_enum import DirEnumAgent
        from agents.recon.api_discover import ApiDiscoverAgent
        from agents.recon.param_discover import ParamDiscoverAgent
        from agents.recon.auth_analysis import AuthAnalysisAgent
        from agents.recon.endpoint_map import EndpointMapAgent
        assert DirEnumAgent is not None

    def test_vuln_analysis_agents(self):
        from agents.vuln_analysis.sqli import SqliVulnAgent
        from agents.vuln_analysis.xss import XssVulnAgent
        from agents.vuln_analysis.ssrf import SsrfVulnAgent
        from agents.vuln_analysis.ssti import SstiVulnAgent
        from agents.vuln_analysis.lfi import LfiVulnAgent
        from agents.vuln_analysis.rce import RceVulnAgent
        from agents.vuln_analysis.jwt import JwtVulnAgent
        from agents.vuln_analysis.upload import UploadVulnAgent
        from agents.vuln_analysis.xxe import XxeVulnAgent
        from agents.vuln_analysis.deser import DeserVulnAgent
        from agents.vuln_analysis.cors import CorsVulnAgent
        from agents.vuln_analysis.idor import IdorVulnAgent
        from agents.vuln_analysis.info_leak import InfoLeakAgent
        assert SqliVulnAgent is not None

    def test_exploitation_agents(self):
        from agents.exploitation.sqli import SqliExploitAgent
        from agents.exploitation.xss import XssExploitAgent
        from agents.exploitation.ssrf import SsrfExploitAgent
        from agents.exploitation.ssti import SstiExploitAgent
        from agents.exploitation.lfi import LfiExploitAgent
        from agents.exploitation.rce import RceExploitAgent
        from agents.exploitation.jwt import JwtExploitAgent
        from agents.exploitation.upload import UploadExploitAgent
        from agents.exploitation.xxe import XxeExploitAgent
        from agents.exploitation.deser import DeserExploitAgent
        from agents.exploitation.idor import IdorExploitAgent
        from agents.exploitation.chain import ChainExploitAgent
        assert SqliExploitAgent is not None

    def test_reporting_agents(self):
        from agents.reporting.evidence_collect import EvidenceCollectAgent
        from agents.reporting.cvss_score import CvssScoreAgent
        from agents.reporting.report_generate import ReportGenerateAgent
        from agents.reporting.compliance_check import ComplianceCheckAgent
        assert EvidenceCollectAgent is not None


class TestAgentExecution:
    """测试 Agent 执行"""

    @pytest.fixture
    def audit(self):
        return AuditSession(session_id="test-session", target="http://example.com")

    @pytest.fixture
    def input_data(self):
        return AgentInput(
            target="http://example.com",
            previous_results={},
        )

    @pytest.mark.asyncio
    async def test_subdomain_agent(self, audit, input_data):
        from agents.pre_recon.subdomain import SubdomainAgent
        agent = SubdomainAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success
        assert "Subdomain Enumeration Report" in result.value.deliverable

    @pytest.mark.asyncio
    async def test_port_scan_agent(self, audit, input_data):
        from agents.pre_recon.port_scan import PortScanAgent
        agent = PortScanAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_tech_detect_agent(self, audit, input_data):
        from agents.pre_recon.tech_detect import TechDetectAgent
        agent = TechDetectAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_dns_info_agent(self, audit, input_data):
        from agents.pre_recon.dns_info import DnsInfoAgent
        agent = DnsInfoAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_js_analyze_agent(self, audit, input_data):
        from agents.pre_recon.js_analyze import JsAnalyzeAgent
        agent = JsAnalyzeAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_dir_enum_agent(self, audit, input_data):
        from agents.recon.dir_enum import DirEnumAgent
        agent = DirEnumAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_api_discover_agent(self, audit, input_data):
        from agents.recon.api_discover import ApiDiscoverAgent
        agent = ApiDiscoverAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_sqli_vuln_agent(self, audit, input_data):
        from agents.vuln_analysis.sqli import SqliVulnAgent
        agent = SqliVulnAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_xss_vuln_agent(self, audit, input_data):
        from agents.vuln_analysis.xss import XssVulnAgent
        agent = XssVulnAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_evidence_collect_agent(self, audit, input_data):
        from agents.reporting.evidence_collect import EvidenceCollectAgent
        agent = EvidenceCollectAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_cvss_score_agent(self, audit, input_data):
        from agents.reporting.cvss_score import CvssScoreAgent
        agent = CvssScoreAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_report_generate_agent(self, audit, input_data):
        from agents.reporting.report_generate import ReportGenerateAgent
        agent = ReportGenerateAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success

    @pytest.mark.asyncio
    async def test_compliance_check_agent(self, audit, input_data):
        from agents.reporting.compliance_check import ComplianceCheckAgent
        agent = ComplianceCheckAgent(audit)
        result = await agent.execute(input_data)
        assert result.ok
        assert result.value.success


class TestChainExploit:
    """测试漏洞链"""

    @pytest.fixture
    def audit(self):
        return AuditSession(session_id="test-session", target="http://example.com")

    @pytest.mark.asyncio
    async def test_chain_with_findings(self, audit):
        from agents.exploitation.chain import ChainExploitAgent
        agent = ChainExploitAgent(audit)
        input_data = AgentInput(
            target="http://example.com",
            previous_results={
                'sqli-vuln': {
                    'findings': [
                        VulnFinding(
                            id="sqli-1",
                            title="SQLi",
                            description="SQL injection",
                            severity="critical",
                            vuln_type="sqli",
                            url="http://example.com/api",
                            classification=VulnClassification.EXPLOITED,
                            classification_reason="test",
                            exploited=True,
                            exploitation_success=True,
                        )
                    ]
                }
            },
        )
        result = await agent.execute(input_data)
        assert result.ok
        # 应该找到 SQLi → Data Dump 链
        assert len(result.value.findings) > 0
