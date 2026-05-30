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


from tools.inject import inject_impl


@mcp.tool()
def inject(url: str, method: str = "POST", param: str = "",
           payloads: list[str] = [], base_payload: str = "test",
           compare_field: str = "body_length", headers: dict = {},
           body_template: str = "", timeout: int = 10) -> dict:
    """Test injection vulnerabilities with custom payloads.

    Claude provides payloads, tool sends them and compares responses.
    Supports: SQLi, XSS, SSTI, XXE, and any custom injection type.
    Returns differential analysis showing which payloads produce different responses.
    """
    result = inject_impl(url=url, method=method, param=param, payloads=payloads,
                         base_payload=base_payload, compare_field=compare_field,
                         headers=headers, body_template=body_template, timeout=timeout)
    kg = get_kg()
    if result.get("analysis", {}).get("likely_vuln"):
        kg.add_finding(type="injection", severity="high", title=f"Possible injection at {param}",
                       detail=result["analysis"]["evidence"],
                       evidence={"url": url, "param": param, "type": result["analysis"]["type"]}, tool="inject")
    for r in result.get("results", []):
        kg.add_attempt(action=f"inject_{param}", target=url, payload=r["payload"],
                       result=r.get("diff_from_base", ""), success=r.get("interesting", False))
    return result


from tools.exec_tool import exec_impl


@mcp.tool()
def exec(code: str, timeout: int = 30) -> dict:
    """Execute Python code for custom exploits and tool integration.

    Safety valve: when predefined tools aren't enough, write code directly.
    Use for: custom payloads, external tool calls (sqlmap/nuclei/hydra),
    data parsing, protocol operations.
    Returns stdout, stderr, exit code, and execution time.
    """
    return exec_impl(code=code, timeout=timeout)


from tools.shell_tool import shell_impl


@mcp.tool()
def shell(action: str = "list", session_id: str = "", type: str = "reverse",
          lhost: str = "", lport: int = 4444, shell_type: str = "bash",
          command: str = "") -> dict:
    """Manage shell sessions.

    Actions:
    - generate: Generate reverse/bind/webshell payload
    - start: Start reverse shell listener (returns session_id)
    - list: List active shell sessions
    - exec: Execute command on active shell
    - close: Close shell session
    """
    result = shell_impl(action=action, session_id=session_id, type=type,
                        lhost=lhost, lport=lport, shell_type=shell_type, command=command)
    kg = get_kg()
    if action == "start" and "session_id" in result:
        kg.add_shell(session_id=result["session_id"], type="reverse", info=f"{lhost}:{lport}")
    return result


from tools.js_analyze import js_analyze_impl


@mcp.tool()
def js_analyze(url: str) -> dict:
    """Analyze JavaScript file for endpoints, secrets, and internal URLs.

    Returns: endpoints, secrets (AWS keys, API keys, JWTs), internal URLs,
    interesting patterns (hardcoded passwords, debug flags, eval usage).
    """
    result = js_analyze_impl(url=url)
    kg = get_kg()
    for secret in result.get("secrets", []):
        kg.add_finding(type="secret", severity="high", title=f"{secret['type']} found in JS",
                       detail=f"Line {secret['line']}: {secret['value'][:50]}",
                       evidence={"url": url, "type": secret["type"]}, tool="js_analyze")
    return result


from tools.src_read import src_read_impl


@mcp.tool()
def src_read(url: str, param: str = "", technique: str = "lfi",
             paths: list[str] = [], method: str = "GET") -> dict:
    """Read files from target via LFI, directory traversal, or source disclosure.

    technique: lfi, git, traversal
    paths: list of file paths to read (e.g., ["/etc/passwd", "/var/www/config.php"])
    Returns full file content for each successfully read file.
    """
    result = src_read_impl(url=url, param=param, technique=technique, paths=paths, method=method)
    kg = get_kg()
    for r in result.get("results", []):
        if r.get("success"):
            kg.add_finding(type="file_read", severity="critical", title=f"File read: {r['path']}",
                           detail=f"Technique: {r.get('technique', 'unknown')}, Size: {r.get('size', 0)}",
                           evidence={"path": r["path"], "technique": r.get("technique")}, tool="src_read")
    return result


from tools.subdomain import subdomain_impl


@mcp.tool()
def subdomain(domain: str, methods: list[str] = ["crtsh", "dns_brute"]) -> dict:
    """Discover subdomains for a domain.

    methods: crtsh (certificate transparency), dns_brute (DNS brute force), subfinder
    Returns subdomains with source and resolved IP.
    """
    return subdomain_impl(domain=domain, methods=methods)


if __name__ == "__main__":
    mcp.run()
