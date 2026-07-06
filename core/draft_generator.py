from datetime import datetime
from pathlib import Path
from typing import Dict

from .burp_import import import_burp_evidence
from .report_filter import ReportFilter
from .vuln_classification import VulnClassification
from .vuln_finding import ProofStrength, SubmissionTier, VulnFinding


def generate_submission_draft_from_burp(
    source_dir: str,
    target: str,
    vuln_slug: str,
    style: str = 'butian',
    destination_dir: str = r'C:\Users\Administrator\.agents\skills\hunter\evidence\tool_output',
    reports_dir: str = r'C:\Users\Administrator\.agents\skills\hunter\reports',
    title: str | None = None,
    business_impact: str | None = None,
) -> Dict[str, str]:
    imported = import_burp_evidence(source_dir, target, vuln_slug, destination_dir)
    report_filter = ReportFilter()
    finding = VulnFinding(
        id=imported['prefix'],
        title=title or f'{vuln_slug.upper()} finding draft',
        description=business_impact or f'{vuln_slug} evidence imported from Burp for manual refinement.',
        severity='high',
        vuln_type=vuln_slug,
        url=target,
        classification=VulnClassification.REPORTABLE,
        submission_tier=SubmissionTier.REPORTABLE,
        reportable=True,
        proof_strength=ProofStrength.STRONG,
        business_impact=business_impact or f'{vuln_slug} has evidence ready for manual final review.',
        impact_scope=target,
        request_file=imported.get('request_file', ''),
        response_file=imported.get('response_file', ''),
        screenshot_files=imported.get('screenshot_files', []),
        evidence_files=imported.get('evidence_files', []),
        request=imported.get('request_file', ''),
        response=imported.get('response_file', ''),
        evidence='Imported from Burp evidence directory.',
    )
    report_filter.filter_findings([finding])
    markdown = report_filter.generate_submission_report(target, style=style)

    reports = Path(reports_dir)
    reports.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = reports / f'{imported["prefix"]}_{style}_{stamp}.md'
    report_path.write_text(markdown, encoding='utf-8')

    return {
        'prefix': imported['prefix'],
        'report_path': str(report_path),
        'request_file': imported.get('request_file', ''),
        'response_file': imported.get('response_file', ''),
    }
