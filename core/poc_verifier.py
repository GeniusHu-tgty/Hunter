from typing import Any, Dict, Optional

from .vuln_classification import VulnClassification
from .vuln_finding import ProofStrength, SubmissionTier, VulnFinding


class PoCVerifier:
    LEAD_ONLY_TYPES = {
        "subdomain",
        "port-scan",
        "tech-detect",
        "dir-enum",
        "js-analyze",
        "api-discover",
        "param-discover",
        "endpoint-map",
        "info-leak",
    }

    def __init__(self, http_client=None, oob_checker=None):
        self.http_client = http_client
        self.oob_checker = oob_checker

    async def verify(self, finding: VulnFinding) -> VulnFinding:
        if finding.vuln_type.lower() in self.LEAD_ONLY_TYPES:
            return self._mark_lead(
                finding,
                reason="该发现默认仅作为线索，不直接构成可提交漏洞。",
                proof_strength=ProofStrength.WEAK,
            )

        if not finding.payload and finding.vuln_type.lower() not in {"idor", "cors"}:
            return self._mark_lead(
                finding,
                reason="缺少可验证载荷，不能进入正式漏洞报告。",
                proof_strength=ProofStrength.NONE,
            )

        verification_result = await self._verify_by_type(finding)
        return self._apply_result(finding, verification_result)

    def _apply_result(self, finding: VulnFinding, result: Dict[str, Any]) -> VulnFinding:
        if result.get("success"):
            finding.classification = result.get("classification", VulnClassification.REPORTABLE)
            finding.classification_reason = result["reason"]
            finding.submission_tier = result.get("submission_tier", SubmissionTier.REPORTABLE)
            finding.reportable = finding.submission_tier in {SubmissionTier.REPORTABLE, SubmissionTier.STRONG}
            finding.exploited = True
            finding.exploitation_success = True
            finding.exploitation_result = result.get("result")
            finding.evidence = result.get("evidence", finding.evidence)
            finding.business_impact = result.get("business_impact", finding.business_impact)
            finding.impact_scope = result.get("impact_scope", finding.impact_scope)
            finding.proof_strength = result.get("proof_strength", ProofStrength.MODERATE)
            finding.review_notes = result.get("review_notes", finding.review_notes)
            finding.src_score = result.get("src_score", self._score_finding(finding))
            finding.why_not_reportable = ""
            return finding

        if result.get("lead", False) or result.get("suspicious", False):
            return self._mark_lead(
                finding,
                reason=result["reason"],
                proof_strength=result.get("proof_strength", ProofStrength.WEAK),
                lead_reason=result.get("lead_reason"),
            )

        finding.classification = VulnClassification.FALSE_POSITIVE
        finding.classification_reason = result["reason"]
        finding.reportable = False
        finding.submission_tier = SubmissionTier.LEAD
        finding.proof_strength = result.get("proof_strength", ProofStrength.NONE)
        finding.why_not_reportable = result["reason"]
        return finding

    def _mark_lead(
        self,
        finding: VulnFinding,
        reason: str,
        proof_strength: ProofStrength,
        lead_reason: Optional[str] = None,
    ) -> VulnFinding:
        finding.classification = VulnClassification.LEAD
        finding.classification_reason = reason
        finding.submission_tier = SubmissionTier.LEAD
        finding.reportable = False
        finding.lead_reason = lead_reason or reason
        finding.why_not_reportable = reason
        finding.proof_strength = proof_strength
        finding.src_score = self._score_finding(finding)
        return finding

    def _score_finding(self, finding: VulnFinding) -> float:
        score = 0.0
        if finding.proof_strength == ProofStrength.STRONG:
            score += 40
        elif finding.proof_strength == ProofStrength.MODERATE:
            score += 25
        elif finding.proof_strength == ProofStrength.WEAK:
            score += 10

        if finding.business_impact:
            score += 20
        if finding.impact_scope:
            score += 15
        score += min(max(finding.confidence, 0.0), 25.0)
        return round(score, 2)

    async def _verify_by_type(self, finding: VulnFinding) -> Dict[str, Any]:
        vuln_type = finding.vuln_type.lower()
        verification_methods = {
            "sqli": self._verify_sqli,
            "xss": self._verify_xss,
            "ssrf": self._verify_ssrf,
            "ssti": self._verify_ssti,
            "lfi": self._verify_lfi,
            "rce": self._verify_rce,
            "xxe": self._verify_xxe,
            "idor": self._verify_idor,
            "cors": self._verify_cors,
            "jwt": self._verify_jwt,
            "upload": self._verify_upload,
        }
        method = verification_methods.get(vuln_type, self._verify_generic)
        return await method(finding)

    async def _verify_sqli(self, finding: VulnFinding) -> Dict[str, Any]:
        time_payload = finding.payload.replace("1=1", "1=1 AND SLEEP(5)")
        response = await self._send_request(finding, time_payload)
        if response and response.get("elapsed", 0) >= 4.5:
            return {
                "success": True,
                "reason": "时间型验证稳定成功。",
                "submission_tier": SubmissionTier.REPORTABLE,
                "classification": VulnClassification.REPORTABLE,
                "proof_strength": ProofStrength.STRONG,
                "evidence": f"响应时间: {response['elapsed']}s",
                "business_impact": "攻击者可稳定触发 SQL 注入行为。",
                "impact_scope": finding.url,
            }

        true_response = await self._send_request(finding, finding.payload)
        false_response = await self._send_request(finding, finding.payload.replace("1=1", "1=2"))
        if true_response and false_response and true_response.get("text", "") != false_response.get("text", ""):
            return {
                "success": True,
                "reason": "布尔差异验证成功。",
                "submission_tier": SubmissionTier.REPORTABLE,
                "classification": VulnClassification.REPORTABLE,
                "proof_strength": ProofStrength.MODERATE,
                "evidence": "真值与假值响应存在稳定差异。",
                "business_impact": "攻击者可操控后端查询逻辑。",
                "impact_scope": finding.url,
            }

        return {
            "success": False,
            "lead": True,
            "reason": "扫描命中但没有稳定 SQL 注入证据，先降为线索。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_xss(self, finding: VulnFinding) -> Dict[str, Any]:
        response = await self._send_request(finding, finding.payload)
        if response and finding.payload in response.get("text", ""):
            return {
                "success": False,
                "lead": True,
                "reason": "仅发现 payload 回显，未证明脚本实际执行。",
                "proof_strength": ProofStrength.WEAK,
                "lead_reason": "XSS 仅回显，不满足正式提交门槛。",
            }
        return {
            "success": False,
            "reason": "未发现可利用的 XSS 证据。",
            "proof_strength": ProofStrength.NONE,
        }

    async def _verify_ssrf(self, finding: VulnFinding) -> Dict[str, Any]:
        if not self.oob_checker:
            return {
                "success": False,
                "lead": True,
                "reason": "缺少 OOB 验证能力，SSRF 先保留为线索。",
                "proof_strength": ProofStrength.WEAK,
            }

        callback_url = self.oob_checker.generate_callback_url()
        await self._send_request(finding, finding.payload.replace("{callback}", callback_url))
        if await self.oob_checker.check_callback(callback_url):
            return {
                "success": True,
                "reason": "收到 OOB 回连，SSRF 验证成功。",
                "submission_tier": SubmissionTier.REPORTABLE,
                "classification": VulnClassification.REPORTABLE,
                "proof_strength": ProofStrength.STRONG,
                "evidence": callback_url,
                "business_impact": "攻击者可诱导服务端向外发起请求。",
                "impact_scope": finding.url,
            }
        return {
            "success": False,
            "lead": True,
            "reason": "存在 SSRF 迹象，但没有回连证据。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_ssti(self, finding: VulnFinding) -> Dict[str, Any]:
        response = await self._send_request(finding, "{{7*7}}")
        if response and "49" in response.get("text", ""):
            return {
                "success": True,
                "reason": "模板表达式执行成功。",
                "submission_tier": SubmissionTier.REPORTABLE,
                "classification": VulnClassification.REPORTABLE,
                "proof_strength": ProofStrength.STRONG,
                "evidence": response.get("text", "")[:200],
                "business_impact": "攻击者可执行模板表达式。",
                "impact_scope": finding.url,
            }
        return {
            "success": False,
            "lead": True,
            "reason": "未拿到可稳定复现的 SSTI 执行证据。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_lfi(self, finding: VulnFinding) -> Dict[str, Any]:
        response = await self._send_request(finding, "../../../../etc/passwd")
        if response and ("root:" in response.get("text", "") or "/bin/bash" in response.get("text", "")):
            return {
                "success": True,
                "reason": "成功读取敏感系统文件。",
                "submission_tier": SubmissionTier.STRONG,
                "classification": VulnClassification.STRONG,
                "proof_strength": ProofStrength.STRONG,
                "evidence": response.get("text", "")[:200],
                "business_impact": "攻击者可读取服务器敏感文件。",
                "impact_scope": finding.url,
            }
        return {
            "success": False,
            "lead": True,
            "reason": "未证明能够读取敏感文件，暂不作为正式漏洞。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_rce(self, finding: VulnFinding) -> Dict[str, Any]:
        response = await self._send_request(finding, finding.payload.replace("{cmd}", "id"))
        if response and ("uid=" in response.get("text", "") or "gid=" in response.get("text", "")):
            return {
                "success": True,
                "reason": "命令执行结果已回显。",
                "submission_tier": SubmissionTier.STRONG,
                "classification": VulnClassification.STRONG,
                "proof_strength": ProofStrength.STRONG,
                "evidence": response.get("text", "")[:200],
                "business_impact": "攻击者可在目标主机执行系统命令。",
                "impact_scope": finding.url,
            }
        return {
            "success": False,
            "lead": True,
            "reason": "未证明命令执行成功。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_xxe(self, finding: VulnFinding) -> Dict[str, Any]:
        if not self.oob_checker:
            return {
                "success": False,
                "lead": True,
                "reason": "缺少 OOB 验证能力，XXE 先保留为线索。",
                "proof_strength": ProofStrength.WEAK,
            }
        callback_url = self.oob_checker.generate_callback_url()
        payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><root>&xxe;</root>'
        await self._send_request(finding, payload)
        if await self.oob_checker.check_callback(callback_url):
            return {
                "success": True,
                "reason": "收到 XXE OOB 回连。",
                "submission_tier": SubmissionTier.REPORTABLE,
                "classification": VulnClassification.REPORTABLE,
                "proof_strength": ProofStrength.STRONG,
                "evidence": callback_url,
                "business_impact": "攻击者可诱导 XML 解析器访问外部资源。",
                "impact_scope": finding.url,
            }
        return {
            "success": False,
            "lead": True,
            "reason": "缺少 XXE 成功利用证据。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_idor(self, finding: VulnFinding) -> Dict[str, Any]:
        response = await self._send_request(finding, finding.payload or "")
        if response and response.get("status", 0) == 200:
            text = response.get("text", "")
            sensitive_patterns = ["email", "password", "token", "secret", "phone", "grade"]
            if any(pattern in text.lower() for pattern in sensitive_patterns):
                return {
                    "success": True,
                    "reason": "访问到了他人真实敏感数据。",
                    "submission_tier": SubmissionTier.STRONG,
                    "classification": VulnClassification.STRONG,
                    "proof_strength": ProofStrength.STRONG,
                    "evidence": text[:200],
                    "business_impact": "低权限用户可访问他人真实敏感数据。",
                    "impact_scope": "任意对象可遍历时影响范围可进一步扩大",
                }
        return {
            "success": False,
            "lead": True,
            "reason": "参数存在越权迹象，但没有拿到足够的数据访问证据。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_cors(self, finding: VulnFinding) -> Dict[str, Any]:
        response = await self._send_request(finding, finding.payload or "")
        if response:
            acao = response.get("headers", {}).get("Access-Control-Allow-Origin", "")
            if acao in {"*", "https://evil.com"}:
                return {
                    "success": False,
                    "lead": True,
                    "reason": "仅 CORS 头异常默认不作为正式漏洞，需要结合敏感接口场景。",
                    "proof_strength": ProofStrength.WEAK,
                }
        return {
            "success": False,
            "reason": "未发现有提交价值的 CORS 证据。",
            "proof_strength": ProofStrength.NONE,
        }

    async def _verify_jwt(self, finding: VulnFinding) -> Dict[str, Any]:
        return {
            "success": False,
            "lead": True,
            "reason": "JWT 问题需要明确伪造或绕过证据，当前仅保留为线索。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_upload(self, finding: VulnFinding) -> Dict[str, Any]:
        return {
            "success": False,
            "lead": True,
            "reason": "未证明上传可造成执行、覆盖或存储型 XSS，仅保留为线索。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _verify_generic(self, finding: VulnFinding) -> Dict[str, Any]:
        return {
            "success": False,
            "lead": True,
            "reason": "未匹配到足够严格的验证规则，默认降为线索。",
            "proof_strength": ProofStrength.WEAK,
        }

    async def _send_request(self, finding: VulnFinding, payload: str) -> Optional[Dict[str, Any]]:
        if not self.http_client:
            return None
        try:
            return await self.http_client.send(
                finding.url,
                method=finding.method,
                param=finding.param,
                payload=payload,
            )
        except Exception:
            return None
