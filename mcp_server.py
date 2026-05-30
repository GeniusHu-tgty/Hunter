"""Hunter v4 — MCP Server

AI-driven pentest agent. Claude is the brain, tools are the hands.
"""

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent))

from fastmcp import FastMCP

from core.knowledge import KnowledgeGraph

# Global state
_kg: KnowledgeGraph | None = None


def get_kg() -> KnowledgeGraph:
    """Get or create the global knowledge graph."""
    global _kg
    if _kg is None:
        _kg = KnowledgeGraph(target="unknown")
    return _kg


def set_target(target: str) -> None:
    """Set the target for the current session."""
    global _kg
    _kg = KnowledgeGraph(target=target)


mcp = FastMCP(
    "Hunter v4",
    instructions="AI-driven pentest agent. 12 tools for recon, analysis, exploitation, and session management.",
)


@mcp.tool()
def session(action: str = "summary", filter_type: str = "", filter_severity: str = "",
            session_id: str = "", export_format: str = "markdown") -> dict:
    """Query or manage the pentest session knowledge graph.

    Actions:
    - summary: Get compact session summary
    - findings: Get all findings (optional filter by type/severity)
    - attempts: Get all exploitation attempts
    - save: Persist session to disk
    - load: Load a previous session
    - export: Export as Markdown report
    """
    kg = get_kg()

    if action == "summary":
        return kg.summary()

    elif action == "findings":
        return {"findings": kg.query_findings(type=filter_type or None, severity=filter_severity or None)}

    elif action == "attempts":
        return {"attempts": kg.query_attempts()}

    elif action == "save":
        path = kg.save()
        return {"saved": path}

    elif action == "load":
        if not session_id:
            return {"error": "session_id required for load action"}
        filepath = Path(__file__).parent / "sessions" / f"{session_id}.json"
        if not filepath.exists():
            return {"error": f"Session file not found: {filepath}"}
        global _kg
        _kg = KnowledgeGraph.load(str(filepath))
        return {"loaded": session_id, "target": _kg.session["target"]}

    elif action == "export":
        return {"report": kg.export_markdown()}

    else:
        return {"error": f"Unknown action: {action}"}


if __name__ == "__main__":
    mcp.run()
