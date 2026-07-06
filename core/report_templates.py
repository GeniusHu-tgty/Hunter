from typing import Dict, List


def _safe_text(value: str, fallback: str = "N/A") -> str:
    text = (value or "").strip()
    return text if text else fallback


def _vuln_type_label(vuln_type: str) -> str:
    mapping = {
        "idor": "越权 / IDOR",
        "auth-bypass": "鉴权绕过",
        "unauthorized": "未授权访问",
        "sqli": "SQL 注入",
        "xss": "跨站脚本",
        "ssrf": "服务端请求伪造",
        "upload": "文件上传",
        "rce": "远程命令执行",
        "ssti": "模板注入",
        "lfi": "本地文件包含",
        "xxe": "XXE",
        "jwt": "JWT 认证问题",
        "info-leak": "信息泄露",
    }
    return mapping.get((vuln_type or "").lower(), vuln_type or "安全问题")


def _default_business_impact(item: Dict[str, str]) -> str:
    vuln_type = (item.get("vuln_type") or "").lower()
    title = item.get("title") or "该问题"
    if vuln_type == "idor":
        return "攻击者可访问不属于自己的业务对象或真实数据，造成越权访问风险。"
    if vuln_type in {"auth-bypass", "unauthorized"}:
        return "攻击者可绕过既有权限边界，直接访问本不应开放的接口或功能。"
    if vuln_type == "ssrf":
        return "攻击者可诱导服务端向指定地址发起请求，可能进一步访问内网或云环境资源。"
    if vuln_type == "upload":
        return "攻击者可利用上传点写入不安全内容，可能进一步导致脚本执行、覆盖文件或存储型 XSS。"
    if vuln_type == "xss":
        return "攻击者可在受害者浏览器中执行脚本，影响会话安全与页面完整性。"
    if vuln_type == "sqli":
        return "攻击者可影响后端查询逻辑，可能进一步读取、篡改或破坏数据库数据。"
    return f"{title} 具备真实安全影响，建议按正式漏洞进行复核与修复。"


def _default_fix(item: Dict[str, str]) -> str:
    vuln_type = (item.get("vuln_type") or "").lower()
    if vuln_type == "idor":
        return "在服务端对目标对象增加严格的归属校验，禁止仅依赖前端参数或可控 ID 判断访问权限。"
    if vuln_type in {"auth-bypass", "unauthorized"}:
        return "在服务端统一补充身份鉴别与权限校验，确保每个敏感接口都进行独立授权检查。"
    if vuln_type == "ssrf":
        return "限制服务端可访问的目标地址范围，禁止访问内网、云元数据与高风险协议，并加入白名单校验。"
    if vuln_type == "upload":
        return "限制上传类型、重命名文件、分离静态资源域并在服务端校验内容，避免任意内容被直接解释执行。"
    if vuln_type == "xss":
        return "对输出内容按上下文进行编码，并对富文本、模板渲染或 DOM 拼接点增加严格过滤。"
    if vuln_type == "sqli":
        return "统一改为参数化查询，并对关键输入点增加白名单约束与异常访问审计。"
    return "在服务端增加严格鉴权、输入验证和业务对象校验逻辑。"


def _default_actual_result(item: Dict[str, str]) -> str:
    return _safe_text(item.get("actual_result") or item.get("business_impact") or item.get("review_notes"), "系统返回了不应返回的行为或数据。")


def _base_report_blocks(target: str, item: Dict[str, str]) -> Dict[str, str]:
    return {
        "title": _safe_text(item.get("title"), "安全问题"),
        "summary": _safe_text(item.get("business_impact"), _default_business_impact(item)),
        "asset": _safe_text(item.get("impact_scope"), target),
        "prerequisites": _safe_text(item.get("prerequisites") or item.get("review_notes"), "已登录或具备基础访问能力。"),
        "expected_result": "系统应拒绝异常请求，并对访问者身份、对象归属及输入合法性进行服务端校验。",
        "actual_result": _default_actual_result(item),
        "impact": _safe_text(item.get("business_impact"), _default_business_impact(item)),
        "remediation": _safe_text(item.get("remediation"), _default_fix(item)),
        "proof_strength": _safe_text(item.get("proof_strength")),
        "evidence": _safe_text(item.get("evidence"), "建议补充请求、响应与截图对比。"),
        "request": _safe_text(item.get("request"), "未记录完整请求，建议补抓包。"),
        "response": _safe_text(item.get("response"), "未记录完整响应，建议补抓包。"),
        "type_label": _vuln_type_label(item.get("vuln_type", "")),
    }




def _appendix_file_lines(item: Dict[str, str]) -> List[str]:
    lines: List[str] = []
    if item.get("request_file"):
        lines.append(f"- Request file: {_safe_text(item.get('request_file'))}")
    if item.get("response_file"):
        lines.append(f"- Response file: {_safe_text(item.get('response_file'))}")
    for path in item.get("screenshot_files", []) or []:
        lines.append(f"- Screenshot: {_safe_text(path)}")
    for path in item.get("evidence_files", []) or []:
        lines.append(f"- Evidence file: {_safe_text(path)}")
    return lines

def render_hackerone_report(target: str, reportable_findings: List[Dict[str, str]], lead_count: int) -> str:
    lines = [
        f"# Hunter HackerOne Submission Draft - {target}",
        "",
        "This draft follows the official HackerOne quality guidance: clear title, reproducible steps, impact, and supporting evidence.",
        "",
    ]
    if not reportable_findings:
        lines.extend([
            "## Summary",
            "No finding currently meets the minimum quality bar for a formal submission.",
            "",
            "## Lead Pool",
            f"{lead_count} lead(s) remain for manual review.",
        ])
        return "\n".join(lines)

    for index, item in enumerate(reportable_findings, 1):
        blocks = _base_report_blocks(target, item)
        lines.extend([
            f"## {index}. {blocks['title']}",
            "",
            "### Summary",
            blocks["summary"],
            "",
            "### Asset",
            blocks["asset"],
            "",
            "### Steps to reproduce",
            "1. Open the target endpoint or feature.",
            "2. Replay the recorded request with the proof-of-concept parameter changes.",
            "3. Compare the response and confirm the unauthorized behavior or dangerous execution result.",
            "",
            "### Expected result",
            blocks["expected_result"],
            "",
            "### Actual result",
            blocks["actual_result"],
            "",
            "### Impact",
            blocks["impact"],
            "",
            "### Supporting material",
            f"- Vulnerability type: {blocks['type_label']}",
            f"- Proof strength: {blocks['proof_strength']}",
            f"- Evidence summary: {blocks['evidence']}",
            f"- Request: {blocks['request']}",
            f"- Response: {blocks['response']}",
            *_appendix_file_lines(item),
            "",
        ])

    lines.extend([
        "## Remaining leads",
        f"{lead_count} lead(s) were intentionally excluded from this submission draft because they do not yet satisfy the formal reporting bar.",
    ])
    return "\n".join(lines)


def render_cn_src_report(target: str, reportable_findings: List[Dict[str, str]], lead_count: int, platform: str = "generic-src") -> str:
    platform_title = {
        "butian": "Hunter 补天 / 国内 SRC 提交草稿",
        "vulbox": "Hunter 漏洞盒子 / 国内 SRC 提交草稿",
        "generic-src": "Hunter 国内 SRC 提交草稿",
    }.get(platform, "Hunter 国内 SRC 提交草稿")

    intro = {
        "butian": "该草稿按补天与国内 SRC 常见审核口径组织：问题概述、复现步骤、预期与实际结果、安全影响、修复建议、附录证据。",
        "vulbox": "该草稿按漏洞盒子与国内 SRC 常见审核口径组织：问题概述、复现步骤、预期与实际结果、安全影响、修复建议、附录证据。",
        "generic-src": "该草稿按国内 SRC 常见审核口径组织：问题概述、复现步骤、预期与实际结果、安全影响、修复建议、附录证据。",
    }.get(platform, "该草稿按国内 SRC 常见审核口径组织：问题概述、复现步骤、预期与实际结果、安全影响、修复建议、附录证据。")

    lines = [
        f"# {platform_title} - {target}",
        "",
        intro,
        "",
    ]

    if not reportable_findings:
        lines.extend([
            "## 漏洞概述",
            "当前没有达到正式提交门槛的漏洞。",
            "",
            "## 线索池摘要",
            f"剩余 {lead_count} 条线索，建议继续人工深挖。",
        ])
        return "\n".join(lines)

    for index, item in enumerate(reportable_findings, 1):
        blocks = _base_report_blocks(target, item)
        lines.extend([
            f"## {index}. {blocks['title']}",
            "",
            "### 漏洞概述",
            blocks["summary"],
            "",
            "### 影响资产 / 范围",
            blocks["asset"],
            "",
            "### 前置条件",
            blocks["prerequisites"],
            "",
            "### 复现步骤",
            "1. 访问目标接口或功能点。",
            "2. 使用附录中的请求并替换关键参数。",
            "3. 观察返回结果并确认出现未授权访问或危险执行行为。",
            "",
            "### 预期结果",
            blocks["expected_result"],
            "",
            "### 实际结果",
            blocks["actual_result"],
            "",
            "### 安全影响",
            blocks["impact"],
            "",
            "### 修复建议",
            blocks["remediation"],
            "",
            "### 附录",
            f"- 漏洞类型：{blocks['type_label']}",
            f"- 证据强度：{blocks['proof_strength']}",
            f"- 证据摘要：{blocks['evidence']}",
            f"- 请求：{blocks['request']}",
            f"- 响应：{blocks['response']}",
            "",
        ])

    lines.extend([
        "## 线索池摘要",
        f"已自动排除 {lead_count} 条暂不满足提交要求的线索，避免污染正式报告。",
    ])
    return "\n".join(lines)
