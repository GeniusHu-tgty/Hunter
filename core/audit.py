import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class AuditEntry:
    timestamp: str
    event: str
    agent: Optional[str]
    details: Dict[str, Any]
    success: Optional[bool] = None
    duration: Optional[float] = None
    error: Optional[str] = None


class AuditSession:
    def __init__(self, session_id: str, target: str):
        self.session_id = session_id
        self.target = target
        self.entries: List[AuditEntry] = []
        self.start_time = datetime.now()
        self.report_data: Dict[str, Any] = {
            "reportable_findings": [],
            "lead_findings": [],
            "summary": {},
        }

    def log_agent_start(self, agent_name: str):
        self.entries.append(
            AuditEntry(
                timestamp=datetime.now().isoformat(),
                event="agent_start",
                agent=agent_name,
                details={"target": self.target},
            )
        )

    def log_agent_end(self, agent_name: str, success: bool, duration: float, result: Any = None):
        self.entries.append(
            AuditEntry(
                timestamp=datetime.now().isoformat(),
                event="agent_end",
                agent=agent_name,
                details={"result": str(result)[:500] if result else None},
                success=success,
                duration=duration,
            )
        )

    def log_vulnerability_found(self, vuln_type: str, url: str, payload: str, evidence: str):
        self.entries.append(
            AuditEntry(
                timestamp=datetime.now().isoformat(),
                event="vulnerability_found",
                agent=None,
                details={
                    "type": vuln_type,
                    "url": url,
                    "payload": payload,
                    "evidence": evidence[:500],
                },
            )
        )

    def log_poc_verification(self, finding_id: str, classification: str, reason: str):
        self.entries.append(
            AuditEntry(
                timestamp=datetime.now().isoformat(),
                event="poc_verification",
                agent=None,
                details={
                    "finding_id": finding_id,
                    "classification": classification,
                    "reason": reason,
                },
            )
        )

    def log_error(self, agent_name: str, error: Exception):
        self.entries.append(
            AuditEntry(
                timestamp=datetime.now().isoformat(),
                event="error",
                agent=agent_name,
                details={"error_type": type(error).__name__},
                error=str(error),
            )
        )

    def log_event(self, event: str, details: Dict[str, Any]):
        self.entries.append(
            AuditEntry(
                timestamp=datetime.now().isoformat(),
                event=event,
                agent=None,
                details=details,
            )
        )

    def set_report_data(
        self,
        reportable_findings: List[Dict[str, Any]],
        lead_findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
    ):
        self.report_data = {
            "reportable_findings": reportable_findings,
            "lead_findings": lead_findings,
            "summary": summary,
        }

    def export_json(self) -> str:
        return json.dumps([asdict(entry) for entry in self.entries], indent=2, ensure_ascii=False)

    def export_report_json(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "reportable_findings": self.report_data.get("reportable_findings", []),
            "lead_findings": self.report_data.get("lead_findings", []),
            "summary": self.report_data.get("summary", {}),
            "audit_log": [asdict(entry) for entry in self.entries],
        }

    def export_markdown(self) -> str:
        lines = [
            f"# Audit Log: {self.session_id}",
            f"Target: {self.target}",
            f"Start: {self.start_time.isoformat()}",
            "",
            "## Entries",
            "",
        ]
        for entry in self.entries:
            lines.append(f"### {entry.timestamp} - {entry.event}")
            if entry.agent:
                lines.append(f"Agent: {entry.agent}")
            if entry.success is not None:
                lines.append(f"Success: {entry.success}")
            if entry.duration:
                lines.append(f"Duration: {entry.duration:.2f}s")
            if entry.error:
                lines.append(f"Error: {entry.error}")
            lines.append("")
        return "\n".join(lines)
