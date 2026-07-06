from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .vuln_classification import VulnClassification


class SubmissionTier(Enum):
    LEAD = "lead"
    REPORTABLE = "reportable"
    STRONG = "strong"


class ProofStrength(Enum):
    NONE = "none"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


@dataclass
class VulnFinding:
    id: str
    vuln_type: str
    title: str
    description: str
    url: str

    classification: VulnClassification = VulnClassification.LEAD
    classification_reason: str = ""

    param: Optional[str] = None
    method: str = "GET"

    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    evidence: Optional[str] = None
    request_file: Optional[str] = None
    response_file: Optional[str] = None
    screenshot_files: List[str] = field(default_factory=list)
    evidence_files: List[str] = field(default_factory=list)

    exploited: bool = False
    exploitation_result: Optional[str] = None
    exploitation_success: bool = False
    exploit_details: Optional[Dict[str, Any]] = None

    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    agent_name: Optional[str] = None
    confidence: float = 0.0

    severity: str = "medium"
    cvss_score: float = 0.0

    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    submission_tier: SubmissionTier = SubmissionTier.LEAD
    reportable: bool = False
    business_impact: str = ""
    impact_scope: str = ""
    proof_strength: ProofStrength = ProofStrength.NONE
    review_notes: str = ""
    lead_reason: str = ""
    src_score: float = 0.0
    why_not_reportable: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "description": self.description,
            "classification": self.classification.value,
            "classification_reason": self.classification_reason,
            "url": self.url,
            "param": self.param,
            "method": self.method,
            "payload": self.payload,
            "request": self.request,
            "response": self.response,
            "evidence": self.evidence,
            "request_file": self.request_file,
            "response_file": self.response_file,
            "screenshot_files": self.screenshot_files,
            "evidence_files": self.evidence_files,
            "exploited": self.exploited,
            "exploitation_result": self.exploitation_result,
            "exploitation_success": self.exploitation_success,
            "timestamp": self.timestamp,
            "agent_name": self.agent_name,
            "confidence": self.confidence,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "references": self.references,
            "submission_tier": self.submission_tier.value,
            "reportable": self.reportable,
            "business_impact": self.business_impact,
            "impact_scope": self.impact_scope,
            "proof_strength": self.proof_strength.value,
            "review_notes": self.review_notes,
            "lead_reason": self.lead_reason,
            "src_score": self.src_score,
            "why_not_reportable": self.why_not_reportable,
        }

    def __str__(self) -> str:
        return f"[{self.submission_tier.value.upper()}] {self.title} @ {self.url}"
