from typing import Any, Dict, List

from .vuln_classification import VulnClassification
from .vuln_finding import SubmissionTier, VulnFinding
from .report_templates import render_cn_src_report, render_hackerone_report


class ReportFilter:
    def __init__(self):
        self.total_findings = 0
        self.reportable_findings: List[VulnFinding] = []
        self.lead_findings: List[VulnFinding] = []
        self.rejected_findings: List[VulnFinding] = []

    def filter_findings(self, findings: List[VulnFinding]) -> List[VulnFinding]:
        self.total_findings = len(findings)
        self.reportable_findings = []
        self.lead_findings = []
        self.rejected_findings = []

        for finding in findings:
            if finding.classification == VulnClassification.FALSE_POSITIVE:
                self.rejected_findings.append(finding)
                continue

            if finding.reportable or finding.submission_tier in {
                SubmissionTier.REPORTABLE,
                SubmissionTier.STRONG,
            } or finding.classification.include_in_report:
                self.reportable_findings.append(finding)
            else:
                self.lead_findings.append(finding)

        self.reportable_findings.sort(
            key=lambda item: (
                0 if item.submission_tier == SubmissionTier.STRONG else 1,
                -item.src_score,
                -item.confidence,
            )
        )
        return self.reportable_findings

    @property
    def exploited_count(self) -> int:
        return len(self.reportable_findings)

    @property
    def potential_count(self) -> int:
        return len(self.lead_findings)

    @property
    def false_positive_count(self) -> int:
        return len(self.rejected_findings)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total": self.total_findings,
            "exploited": self.exploited_count,
            "potential": self.potential_count,
            "false_positive": self.false_positive_count,
            "reportable": self.exploited_count,
            "leads": self.potential_count,
            "filter_rate": self.exploited_count / self.total_findings if self.total_findings else 0.0,
        }

    def generate_summary(self) -> str:
        stats = self.get_statistics()
        return (
            "## SRC 严审模式统计\n\n"
            f"- 正式漏洞: {stats['reportable']}\n"
            f"- 线索池: {stats['leads']}\n"
            f"- 丢弃项: {stats['false_positive']}\n"
            f"- 总发现数: {stats['total']}\n"
        )

    def generate_submission_report(self, target: str, style: str = "cn-src") -> str:
        reportable = [finding.to_dict() for finding in self.reportable_findings]
        lead_count = len(self.lead_findings)
        if style == "hackerone":
            return render_hackerone_report(target, reportable, lead_count)
        if style == "butian":
            return render_cn_src_report(target, reportable, lead_count, platform="butian")
        if style == "vulbox":
            return render_cn_src_report(target, reportable, lead_count, platform="vulbox")
        return render_cn_src_report(target, reportable, lead_count, platform="generic-src")

    def generate_lead_report(self) -> str:
        if not self.lead_findings:
            return "# Hunter Lead Pool\n\n当前无线索池内容。"

        lines = [
            "# Hunter Lead Pool",
            "",
            "以下内容仅作为继续深挖的线索，不应直接提交为漏洞：",
            "",
        ]
        for index, finding in enumerate(self.lead_findings, 1):
            lines.extend([
                f"## {index}. {finding.title}",
                "",
                f"- **类型**: {finding.vuln_type}",
                f"- **URL**: {finding.url}",
                f"- **线索原因**: {finding.lead_reason or finding.why_not_reportable or finding.classification_reason}",
                f"- **证据强度**: {finding.proof_strength.value}",
                "",
            ])
        return "\n".join(lines)

    def generate_potential_report(self) -> str:
        return self.generate_lead_report()
