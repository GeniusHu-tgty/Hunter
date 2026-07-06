"""
Agent 定义 - 39 个 Agent

包含：
- Phase 1: Pre-recon (5 个)
- Phase 2: Recon (5 个)
- Phase 3: Vulnerability Analysis (13 个)
- Phase 4: Exploitation (12 个)
- Phase 5: Reporting (4 个)
"""

from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from enum import Enum


class ModelTier(Enum):
    """模型层级"""
    SMALL = "small"        # Haiku - 快速、便宜
    STANDARD = "standard"  # Sonnet - 平衡
    LARGE = "large"        # Opus - 深度推理


@dataclass
class AgentDefinition:
    """Agent 定义"""
    name: str
    display_name: str
    description: str
    prerequisites: List[str]
    prompt_template: str
    deliverable_filename: str
    model_tier: ModelTier = ModelTier.STANDARD
    max_retries: int = 3
    timeout: int = 300
    parallel_safe: bool = True
    tools_required: List[str] = field(default_factory=list)
    payload_types: List[str] = field(default_factory=list)


AGENTS: Dict[str, AgentDefinition] = {
    # ============================================
    # Phase 1: Pre-recon Agents
    # ============================================

    "subdomain": AgentDefinition(
        name="subdomain",
        display_name="Subdomain Enumeration Agent",
        description="枚举目标子域名，发现攻击面",
        prerequisites=[],
        prompt_template="pre-recon-subdomain",
        deliverable_filename="subdomain_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["subdomain", "dns"],
    ),

    "port-scan": AgentDefinition(
        name="port-scan",
        display_name="Port Scan Agent",
        description="扫描目标端口，识别开放服务",
        prerequisites=[],
        prompt_template="pre-recon-port-scan",
        deliverable_filename="port_scan_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["port_scan"],
    ),

    "tech-detect": AgentDefinition(
        name="tech-detect",
        display_name="Technology Detection Agent",
        description="识别目标技术栈（框架、语言、服务器）",
        prerequisites=[],
        prompt_template="pre-recon-tech-detect",
        deliverable_filename="tech_detect_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["tech", "probe"],
    ),

    "dns-info": AgentDefinition(
        name="dns-info",
        display_name="DNS Information Agent",
        description="收集 DNS 信息（A/MX/TXT/NS 记录）",
        prerequisites=[],
        prompt_template="pre-recon-dns-info",
        deliverable_filename="dns_info_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["dns"],
    ),

    "js-analyze": AgentDefinition(
        name="js-analyze",
        display_name="JavaScript Analysis Agent",
        description="分析 JS 文件，提取端点、密钥、内部 URL",
        prerequisites=[],
        prompt_template="pre-recon-js-analyze",
        deliverable_filename="js_analyze_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["js_analyze"],
    ),

    # ============================================
    # Phase 2: Recon Agents
    # ============================================

    "dir-enum": AgentDefinition(
        name="dir-enum",
        display_name="Directory Enumeration Agent",
        description="枚举目录和文件，发现隐藏路径",
        prerequisites=["subdomain", "port-scan"],
        prompt_template="recon-dir-enum",
        deliverable_filename="dir_enum_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["dir_enum", "fuzz"],
    ),

    "api-discover": AgentDefinition(
        name="api-discover",
        display_name="API Discovery Agent",
        description="发现 API 端点（REST/GraphQL/WebSocket）",
        prerequisites=["subdomain", "port-scan"],
        prompt_template="recon-api-discover",
        deliverable_filename="api_discover_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["js_analyze", "probe"],
    ),

    "param-discover": AgentDefinition(
        name="param-discover",
        display_name="Parameter Discovery Agent",
        description="发现隐藏参数（从 JS/HTML 提取）",
        prerequisites=["subdomain", "port-scan"],
        prompt_template="recon-param-discover",
        deliverable_filename="param_discover_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["js_analyze", "fuzz"],
    ),

    "auth-analysis": AgentDefinition(
        name="auth-analysis",
        display_name="Authentication Analysis Agent",
        description="分析认证机制（Cookie/Token/Session）",
        prerequisites=["subdomain", "port-scan"],
        prompt_template="recon-auth-analysis",
        deliverable_filename="auth_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["probe", "api_test"],
    ),

    "endpoint-map": AgentDefinition(
        name="endpoint-map",
        display_name="Endpoint Mapping Agent",
        description="映射所有端点，构建攻击面地图",
        prerequisites=["subdomain", "port-scan"],
        prompt_template="recon-endpoint-map",
        deliverable_filename="endpoint_map_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["js_analyze", "probe"],
    ),

    # ============================================
    # Phase 3: Vulnerability Analysis Agents
    # ============================================

    "sqli-vuln": AgentDefinition(
        name="sqli-vuln",
        display_name="SQL Injection Vulnerability Agent",
        description="检测 SQL 注入漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-sqli",
        deliverable_filename="sqli_analysis_deliverable.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "fuzz"],
        payload_types=["sqli"],
    ),

    "xss-vuln": AgentDefinition(
        name="xss-vuln",
        display_name="XSS Vulnerability Agent",
        description="检测跨站脚本漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-xss",
        deliverable_filename="xss_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "fuzz"],
        payload_types=["xss"],
    ),

    "ssrf-vuln": AgentDefinition(
        name="ssrf-vuln",
        display_name="SSRF Vulnerability Agent",
        description="检测服务端请求伪造漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-ssrf",
        deliverable_filename="ssrf_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "oob"],
        payload_types=["ssrf"],
    ),

    "ssti-vuln": AgentDefinition(
        name="ssti-vuln",
        display_name="SSTI Vulnerability Agent",
        description="检测服务端模板注入漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-ssti",
        deliverable_filename="ssti_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "fuzz"],
        payload_types=["ssti"],
    ),

    "lfi-vuln": AgentDefinition(
        name="lfi-vuln",
        display_name="LFI Vulnerability Agent",
        description="检测本地文件包含漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-lfi",
        deliverable_filename="lfi_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "fuzz"],
        payload_types=["lfi"],
    ),

    "rce-vuln": AgentDefinition(
        name="rce-vuln",
        display_name="RCE Vulnerability Agent",
        description="检测远程命令执行漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-rce",
        deliverable_filename="rce_analysis_deliverable.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "oob"],
        payload_types=["rce"],
    ),

    "jwt-vuln": AgentDefinition(
        name="jwt-vuln",
        display_name="JWT Vulnerability Agent",
        description="检测 JWT 漏洞（算法混淆、密钥弱）",
        prerequisites=["recon"],
        prompt_template="vuln-jwt",
        deliverable_filename="jwt_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["api_test"],
        payload_types=["jwt"],
    ),

    "upload-vuln": AgentDefinition(
        name="upload-vuln",
        display_name="File Upload Vulnerability Agent",
        description="检测文件上传漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-upload",
        deliverable_filename="upload_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "fuzz"],
        payload_types=["upload"],
    ),

    "xxe-vuln": AgentDefinition(
        name="xxe-vuln",
        display_name="XXE Vulnerability Agent",
        description="检测 XML 外部实体注入漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-xxe",
        deliverable_filename="xxe_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "oob"],
        payload_types=["xxe"],
    ),

    "deser-vuln": AgentDefinition(
        name="deser-vuln",
        display_name="Deserialization Vulnerability Agent",
        description="检测反序列化漏洞（PHP/Java/Python）",
        prerequisites=["recon"],
        prompt_template="vuln-deser",
        deliverable_filename="deser_analysis_deliverable.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "deser"],
        payload_types=["deser"],
    ),

    "cors-vuln": AgentDefinition(
        name="cors-vuln",
        display_name="CORS Vulnerability Agent",
        description="检测 CORS 配置错误",
        prerequisites=["recon"],
        prompt_template="vuln-cors",
        deliverable_filename="cors_analysis_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["passive_scan"],
    ),

    "idor-vuln": AgentDefinition(
        name="idor-vuln",
        display_name="IDOR Vulnerability Agent",
        description="检测 IDOR（不安全的直接对象引用）漏洞",
        prerequisites=["recon"],
        prompt_template="vuln-idor",
        deliverable_filename="idor_analysis_deliverable.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "api_test"],
    ),

    "info-leak": AgentDefinition(
        name="info-leak",
        display_name="Information Leak Agent",
        description="检测信息泄露（配置文件、日志、备份）",
        prerequisites=["recon"],
        prompt_template="vuln-info-leak",
        deliverable_filename="info_leak_analysis_deliverable.md",
        model_tier=ModelTier.SMALL,
        tools_required=["passive_scan", "dir_enum"],
        payload_types=["info_leak"],
    ),

    # ============================================
    # Phase 4: Exploitation Agents
    # ============================================

    "sqli-exploit": AgentDefinition(
        name="sqli-exploit",
        display_name="SQL Injection Exploitation Agent",
        description="利用 SQL 注入漏洞获取数据",
        prerequisites=["sqli-vuln"],
        prompt_template="exploit-sqli",
        deliverable_filename="sqli_exploitation_evidence.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "sqli_exploit"],
        payload_types=["sqli"],
    ),

    "xss-exploit": AgentDefinition(
        name="xss-exploit",
        display_name="XSS Exploitation Agent",
        description="利用 XSS 漏洞窃取数据",
        prerequisites=["xss-vuln"],
        prompt_template="exploit-xss",
        deliverable_filename="xss_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject"],
        payload_types=["xss"],
    ),

    "ssrf-exploit": AgentDefinition(
        name="ssrf-exploit",
        display_name="SSRF Exploitation Agent",
        description="利用 SSRF 漏洞访问内部资源",
        prerequisites=["ssrf-vuln"],
        prompt_template="exploit-ssrf",
        deliverable_filename="ssrf_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "oob"],
        payload_types=["ssrf"],
    ),

    "ssti-exploit": AgentDefinition(
        name="ssti-exploit",
        display_name="SSTI Exploitation Agent",
        description="利用 SSTI 漏洞执行命令",
        prerequisites=["ssti-vuln"],
        prompt_template="exploit-ssti",
        deliverable_filename="ssti_exploitation_evidence.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject"],
        payload_types=["ssti"],
    ),

    "lfi-exploit": AgentDefinition(
        name="lfi-exploit",
        display_name="LFI Exploitation Agent",
        description="利用 LFI 漏洞读取文件",
        prerequisites=["lfi-vuln"],
        prompt_template="exploit-lfi",
        deliverable_filename="lfi_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject"],
        payload_types=["lfi"],
    ),

    "rce-exploit": AgentDefinition(
        name="rce-exploit",
        display_name="RCE Exploitation Agent",
        description="利用 RCE 漏洞执行命令",
        prerequisites=["rce-vuln"],
        prompt_template="exploit-rce",
        deliverable_filename="rce_exploitation_evidence.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "shell"],
        payload_types=["rce"],
    ),

    "jwt-exploit": AgentDefinition(
        name="jwt-exploit",
        display_name="JWT Exploitation Agent",
        description="利用 JWT 漏洞伪造 Token",
        prerequisites=["jwt-vuln"],
        prompt_template="exploit-jwt",
        deliverable_filename="jwt_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["api_test"],
        payload_types=["jwt"],
    ),

    "upload-exploit": AgentDefinition(
        name="upload-exploit",
        display_name="File Upload Exploitation Agent",
        description="利用文件上传漏洞获取 Webshell",
        prerequisites=["upload-vuln"],
        prompt_template="exploit-upload",
        deliverable_filename="upload_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject"],
        payload_types=["upload"],
    ),

    "xxe-exploit": AgentDefinition(
        name="xxe-exploit",
        display_name="XXE Exploitation Agent",
        description="利用 XXE 漏洞读取文件或 SSRF",
        prerequisites=["xxe-vuln"],
        prompt_template="exploit-xxe",
        deliverable_filename="xxe_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "oob"],
        payload_types=["xxe"],
    ),

    "deser-exploit": AgentDefinition(
        name="deser-exploit",
        display_name="Deserialization Exploitation Agent",
        description="利用反序列化漏洞执行命令",
        prerequisites=["deser-vuln"],
        prompt_template="exploit-deser",
        deliverable_filename="deser_exploitation_evidence.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "deser"],
        payload_types=["deser"],
    ),

    "idor-exploit": AgentDefinition(
        name="idor-exploit",
        display_name="IDOR Exploitation Agent",
        description="利用 IDOR 漏洞访问其他用户数据",
        prerequisites=["idor-vuln"],
        prompt_template="exploit-idor",
        deliverable_filename="idor_exploitation_evidence.md",
        model_tier=ModelTier.STANDARD,
        tools_required=["inject", "api_test"],
    ),

    "chain-exploit": AgentDefinition(
        name="chain-exploit",
        display_name="Chain Exploitation Agent",
        description="利用漏洞链组合攻击",
        prerequisites=["sqli-vuln", "ssrf-vuln", "upload-vuln"],
        prompt_template="exploit-chain",
        deliverable_filename="chain_exploitation_evidence.md",
        model_tier=ModelTier.LARGE,
        tools_required=["inject", "oob", "shell"],
    ),

    # ============================================
    # Phase 5: Reporting Agents
    # ============================================

    "evidence-collect": AgentDefinition(
        name="evidence-collect",
        display_name="Evidence Collection Agent",
        description="收集漏洞证据",
        prerequisites=["exploitation"],
        prompt_template="report-evidence",
        deliverable_filename="evidence_collection.md",
        model_tier=ModelTier.SMALL,
    ),

    "cvss-score": AgentDefinition(
        name="cvss-score",
        display_name="CVSS Scoring Agent",
        description="计算 CVSS 评分",
        prerequisites=["exploitation"],
        prompt_template="report-cvss",
        deliverable_filename="cvss_scores.md",
        model_tier=ModelTier.SMALL,
    ),

    "report-generate": AgentDefinition(
        name="report-generate",
        display_name="Report Generation Agent",
        description="生成专业报告",
        prerequisites=["evidence-collect", "cvss-score"],
        prompt_template="report-generate",
        deliverable_filename="security_report.md",
        model_tier=ModelTier.STANDARD,
    ),

    "compliance-check": AgentDefinition(
        name="compliance-check",
        display_name="Compliance Check Agent",
        description="检查合规性",
        prerequisites=["report-generate"],
        prompt_template="report-compliance",
        deliverable_filename="compliance_report.md",
        model_tier=ModelTier.SMALL,
    ),
}

# 从 typing 导入 Dict
from typing import Dict
