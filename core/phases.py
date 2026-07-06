"""
阶段定义 - 5 阶段流水线

Phase 1: Pre-recon (预侦察) - 被动信息收集
Phase 2: Recon (侦察) - 主动信息收集
Phase 3: Vulnerability Analysis (漏洞分析) - 并行漏洞检测
Phase 4: Exploitation (漏洞利用) - 验证漏洞可利用性
Phase 5: Reporting (报告) - 生成专业报告
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict


class PhaseName(Enum):
    """阶段名称"""
    PRE_RECON = "pre-recon"
    RECON = "recon"
    VULN_ANALYSIS = "vulnerability-analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


@dataclass
class PhaseConfig:
    """阶段配置"""
    name: PhaseName
    display_name: str
    agents: List[str]
    prerequisites: List[PhaseName]
    parallel: bool = True
    max_agents: int = 10


PHASES: Dict[PhaseName, PhaseConfig] = {
    PhaseName.PRE_RECON: PhaseConfig(
        name=PhaseName.PRE_RECON,
        display_name="Pre-reconnaissance",
        agents=["subdomain", "port-scan", "tech-detect", "dns-info", "js-analyze"],
        prerequisites=[],
        parallel=True,
    ),
    PhaseName.RECON: PhaseConfig(
        name=PhaseName.RECON,
        display_name="Reconnaissance",
        agents=["dir-enum", "api-discover", "param-discover", "auth-analysis", "endpoint-map"],
        prerequisites=[PhaseName.PRE_RECON],
        parallel=True,
    ),
    PhaseName.VULN_ANALYSIS: PhaseConfig(
        name=PhaseName.VULN_ANALYSIS,
        display_name="Vulnerability Analysis",
        agents=[
            "sqli-vuln", "xss-vuln", "ssrf-vuln", "ssti-vuln", "lfi-vuln",
            "rce-vuln", "jwt-vuln", "upload-vuln", "xxe-vuln", "deser-vuln",
            "cors-vuln", "idor-vuln", "info-leak",
        ],
        prerequisites=[PhaseName.RECON],
        parallel=True,
    ),
    PhaseName.EXPLOITATION: PhaseConfig(
        name=PhaseName.EXPLOITATION,
        display_name="Exploitation",
        agents=[
            "sqli-exploit", "xss-exploit", "ssrf-exploit", "ssti-exploit", "lfi-exploit",
            "rce-exploit", "jwt-exploit", "upload-exploit", "xxe-exploit", "deser-exploit",
            "idor-exploit", "chain-exploit",
        ],
        prerequisites=[PhaseName.VULN_ANALYSIS],
        parallel=True,
    ),
    PhaseName.REPORTING: PhaseConfig(
        name=PhaseName.REPORTING,
        display_name="Reporting",
        agents=["evidence-collect", "cvss-score", "report-generate", "compliance-check"],
        prerequisites=[PhaseName.EXPLOITATION],
        parallel=False,
    ),
}
