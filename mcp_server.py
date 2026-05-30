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


from tools.probe import probe_impl


@mcp.tool()
def probe(url: str, method: str = "GET", headers: dict = {}, body: str = "",
          follow_redirects: bool = True, timeout: int = 10) -> dict:
    """Send HTTP request to target and analyze response.

    Returns full response (headers, body, cookies, timing) plus
    auto-detected interesting content (forms, comments, leaks, errors).
    Use this for all HTTP operations: GET, POST, PUT, DELETE, etc.
    """
    result = probe_impl(url=url, method=method, headers=headers, body=body,
                        follow_redirects=follow_redirects, timeout=timeout)
    kg = get_kg()
    if result.get("interesting"):
        kg.add_finding(
            type="observation",
            severity="info",
            title=f"Interesting content at {url}",
            detail="; ".join(result["interesting"][:3]),
            evidence={"url": url, "status": result["status"]},
            tool="probe"
        )
    return result


from tools.dns_tool import dns_impl
from tools.port_scan import port_scan_impl


@mcp.tool()
def port_scan(host: str, ports: str = "top100", timeout: int = 3) -> dict:
    """Scan ports on target host.

    ports: "top100", "top1000", "22,80,443", "1-1024"
    Returns only open ports with service/version info.
    """
    result = port_scan_impl(host=host, ports=ports, timeout=timeout)
    kg = get_kg()
    for p in result["open"]:
        kg.add_finding(
            type="open_port",
            severity="info",
            title=f"Port {p['port']} ({p['service']}) open on {host}",
            detail=f"Service: {p['service']}, Version: {p['version']}",
            evidence={"host": host, "port": p["port"], "service": p["service"]},
            tool="port_scan"
        )
    return result


@mcp.tool()
def dns(domain: str, type: str = "ANY") -> dict:
    """Resolve DNS records for a domain.

    type: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, or ANY
    Returns all discovered records with type, value, and TTL.
    """
    return dns_impl(domain=domain, record_type=type)


from tools.dir_enum import dir_enum_impl


@mcp.tool()
def dir_enum(url: str, wordlist: str = "default", extensions: list[str] = [],
             max_results: int = 50, timeout: int = 5) -> dict:
    """Enumerate directories and files on target web server.

    Returns only interesting paths (non-404, non-baseline).
    Uses threaded Python scanner with intelligent filtering.
    """
    result = dir_enum_impl(url=url, wordlist=wordlist, extensions=extensions,
                           max_results=max_results, timeout=timeout)
    kg = get_kg()
    for f in result.get("found", []):
        if f.get("interesting"):
            kg.add_finding(
                type="directory",
                severity="medium" if any(s in f["path"].lower() for s in [".git", ".env", "backup", "config"]) else "low",
                title=f"Interesting path: {f['path']}",
                detail=f"Status: {f['status']}, Size: {f['size']}",
                evidence={"url": f"{url}{f['path']}", "status": f["status"]},
                tool="dir_enum"
            )
    return result


from tools.tech import tech_impl


@mcp.tool()
def tech(url: str) -> dict:
    """Identify technologies used by target web application.

    Detects: framework, language, server, CMS, WAF.
    Returns evidence for each detection and known vulnerabilities.
    """
    result = tech_impl(url=url)
    kg = get_kg()
    techs = result.get("technologies", {})
    if techs.get("framework"):
        kg.add_finding(
            type="technology",
            severity="info",
            title=f"Framework: {techs['framework']}",
            detail=f"Server: {techs['server']}, Language: {techs['language']}",
            evidence=result.get("evidence", {}),
            tool="tech"
        )
    if result.get("known_vulns"):
        for vuln in result["known_vulns"]:
            kg.add_finding(
                type="potential_vuln",
                severity="high",
                title=vuln,
                detail=f"Detected from technology fingerprint at {url}",
                evidence={"url": url},
                tool="tech"
            )
    return result


if __name__ == "__main__":
    mcp.run()
