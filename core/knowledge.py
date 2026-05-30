"""Hunter v4 — Knowledge Graph

JSON-based knowledge graph for pentest session state.
Tracks findings, attempts, shells, and attack paths.
Persists to disk for cross-session continuity.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


SESSIONS_DIR = Path(__file__).parent.parent / "sessions"
SESSIONS_DIR.mkdir(exist_ok=True)


class KnowledgeGraph:
    """Pentest session knowledge graph with JSON persistence."""

    def __init__(self, target: str, session_id: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        self.session = {
            "target": target,
            "session_id": session_id or f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "started_at": now,
            "findings": [],
            "attempts": [],
            "shells": [],
            "attack_paths": [],
        }
        self._finding_counter = 0

    def add_finding(self, type: str, severity: str, title: str, detail: str,
                    evidence: dict, tool: str) -> dict:
        """Record a vulnerability or information finding."""
        self._finding_counter += 1
        finding = {
            "id": f"f{self._finding_counter:03d}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": type,
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence,
            "tool": tool,
        }
        self.session["findings"].append(finding)
        return finding

    def add_attempt(self, action: str, target: str, payload: str, result: str,
                    success: bool, **kwargs) -> dict:
        """Record an exploitation attempt (success or failure)."""
        attempt = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "payload": payload,
            "result": result,
            "success": success,
            **kwargs,
        }
        self.session["attempts"].append(attempt)
        return attempt

    def add_shell(self, session_id: str, type: str, info: str = "") -> dict:
        """Record a shell session."""
        shell = {
            "session_id": session_id,
            "type": type,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "info": info,
        }
        self.session["shells"].append(shell)
        return shell

    def add_attack_path(self, path: str) -> None:
        """Record an attack path (chain of findings)."""
        if path not in self.session["attack_paths"]:
            self.session["attack_paths"].append(path)

    def summary(self) -> dict:
        """Return a compact summary of the session."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.session["findings"]:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        active_shells = sum(1 for s in self.session["shells"] if s["status"] == "active")
        success_attempts = sum(1 for a in self.session["attempts"] if a["success"])

        return {
            "target": self.session["target"],
            "session_id": self.session["session_id"],
            "started_at": self.session["started_at"],
            "findings_count": len(self.session["findings"]),
            "findings_summary": severity_counts,
            "top_findings": [
                {"type": f["type"], "severity": f["severity"], "title": f["title"]}
                for f in self.session["findings"]
                if f["severity"] in ("critical", "high")
            ],
            "attempts_count": len(self.session["attempts"]),
            "attempts_successful": success_attempts,
            "shells_active": active_shells,
            "attack_paths": self.session["attack_paths"],
        }

    def query_findings(self, type: Optional[str] = None, severity: Optional[str] = None) -> list:
        """Query findings with optional filters."""
        results = self.session["findings"]
        if type:
            results = [f for f in results if f["type"] == type]
        if severity:
            results = [f for f in results if f["severity"] == severity]
        return results

    def query_attempts(self, success: Optional[bool] = None, action: Optional[str] = None) -> list:
        """Query attempts with optional filters."""
        results = self.session["attempts"]
        if success is not None:
            results = [a for a in results if a["success"] == success]
        if action:
            results = [a for a in results if a["action"] == action]
        return results

    def save(self, directory: Optional[str] = None) -> str:
        """Persist session to JSON file."""
        save_dir = Path(directory) if directory else SESSIONS_DIR
        save_dir.mkdir(parents=True, exist_ok=True)
        filepath = save_dir / f"{self.session['session_id']}.json"
        with open(filepath, "w") as f:
            json.dump(self.session, f, indent=2, ensure_ascii=False)
        return str(filepath)

    @classmethod
    def load(cls, filepath: str) -> "KnowledgeGraph":
        """Load session from JSON file."""
        with open(filepath) as f:
            data = json.load(f)
        kg = cls(target=data["target"], session_id=data["session_id"])
        kg.session = data
        kg._finding_counter = len(data["findings"])
        return kg

    def export_markdown(self) -> str:
        """Export session as Markdown report."""
        s = self.summary()
        lines = [
            f"# Hunter v4 Pentest Report",
            f"",
            f"**Target:** {s['target']}",
            f"**Session:** {s['session_id']}",
            f"**Started:** {s['started_at']}",
            f"",
            f"## Summary",
            f"- Findings: {s['findings_count']}",
            f"- Critical: {s['findings_summary']['critical']}",
            f"- High: {s['findings_summary']['high']}",
            f"- Medium: {s['findings_summary']['medium']}",
            f"- Low: {s['findings_summary']['low']}",
            f"- Successful attempts: {s['attempts_successful']}/{s['attempts_count']}",
            f"- Active shells: {s['shells_active']}",
            f"",
        ]

        if s["attack_paths"]:
            lines.append("## Attack Paths")
            for path in s["attack_paths"]:
                lines.append(f"- {path}")
            lines.append("")

        if self.session["findings"]:
            lines.append("## Findings")
            for f in self.session["findings"]:
                lines.append(f"### [{f['severity'].upper()}] {f['title']}")
                lines.append(f"- **Type:** {f['type']}")
                lines.append(f"- **Tool:** {f['tool']}")
                lines.append(f"- **Detail:** {f['detail']}")
                if f["evidence"]:
                    lines.append(f"- **Evidence:** `{json.dumps(f['evidence'], ensure_ascii=False)}`")
                lines.append("")

        return "\n".join(lines)
