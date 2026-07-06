from typing import Dict, List

from .audit import AuditSession
from .poc_verifier import PoCVerifier
from .report_filter import ReportFilter
from .vuln_finding import VulnFinding


class PoCWorkflow:
    def __init__(
        self,
        poc_verifier: PoCVerifier,
        report_filter: ReportFilter,
        audit_session: AuditSession,
    ):
        self.verifier = poc_verifier
        self.filter = report_filter
        self.audit = audit_session

    async def process_findings(self, raw_findings: List[VulnFinding]) -> List[VulnFinding]:
        self.audit.log_event("poc_workflow_start", {"total_findings": len(raw_findings)})

        verified_findings: List[VulnFinding] = []
        for finding in raw_findings:
            self.audit.log_event(
                "verifying_finding",
                {"id": finding.id, "vuln_type": finding.vuln_type},
            )
            verified = await self.verifier.verify(finding)
            verified_findings.append(verified)
            self.audit.log_event(
                "finding_verified",
                {
                    "id": finding.id,
                    "classification": verified.classification.value,
                    "submission_tier": verified.submission_tier.value,
                    "reportable": verified.reportable,
                },
            )

        report_findings = self.filter.filter_findings(verified_findings)
        stats = self.filter.get_statistics()
        self.audit.log_event("poc_workflow_complete", stats)
        self.audit.log_event("workflow_summary", {"summary": self.filter.generate_summary()})
        self.audit.set_report_data(
            reportable_findings=[finding.to_dict() for finding in self.filter.reportable_findings],
            lead_findings=[finding.to_dict() for finding in self.filter.lead_findings],
            summary=stats,
        )
        return report_findings

    def get_statistics(self) -> Dict[str, int]:
        return self.filter.get_statistics()

    def generate_report(self) -> str:
        return self.filter.generate_submission_report(self.audit.target)

    def generate_potential_report(self) -> str:
        return self.filter.generate_potential_report()
