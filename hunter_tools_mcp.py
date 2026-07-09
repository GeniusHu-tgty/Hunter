
"""Hunter Tools v8.1 MCP server.

ReverseLabTools-style entrypoint: thin FastMCP wrappers returning Python dicts.
The legacy root mcp_server.py keeps JSON-string compatibility; this module is
intended for a future `hunter_tools` MCP registration.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP

HUNTER_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(HUNTER_DIR))

from core.hunter_tools_facade import HunterToolsFacade

mcp = FastMCP(
    "hunter_tools",
    instructions=(
        "Hunter v8.1 reverse_lab_tools-compatible facade. Use hunter_kb_* "
        "for Hunter knowledge base routing and hunter_burp_* for Burp MCP "
        "action plans; use legacy hunter server for scanners until migrated."
    ),
)

_facade = HunterToolsFacade(HUNTER_DIR)


@mcp.tool()
async def hunter_kb_list() -> dict:
    """List Hunter technique markdown files and payload YAML inventory."""
    return _facade.kb_list()


@mcp.tool()
async def hunter_kb_search(query: str, limit: int = 20) -> dict:
    """Search Hunter KB by signal/query."""
    return _facade.kb_search(query, limit=limit)


@mcp.tool()
async def hunter_kb_read(technique_path: str, max_chars: int = 12000) -> dict:
    """Read exact Hunter KB file under payloads/."""
    return _facade.kb_read(technique_path, max_chars=max_chars)


@mcp.tool()
async def hunter_kb_recommend(signals: Optional[List[str]] = None, finding: str = "", target: str = "", limit: int = 8) -> dict:
    """Recommend Hunter KB files, payloads, tools and Burp proof actions."""
    return _facade.kb_recommend(signals=signals or [], finding=finding, target=target, limit=limit)


@mcp.tool()
async def hunter_burp_bridge(action: str, url: str = "", method: str = "GET", headers: Optional[Dict[str, str]] = None,
                             body: str = "", http2: bool = True, regex: str = "", count: int = 50,
                             offset: int = 0, severity_filter: str = "", tab_name: str = "") -> dict:
    """Generic Burp bridge action descriptor builder."""
    kwargs = {
        "url": url or None,
        "method": method,
        "headers": headers or {},
        "body": body,
        "http2": http2,
        "regex": regex or None,
        "count": count,
        "offset": offset,
        "severity_filter": severity_filter,
        "tab_name": tab_name,
    }
    return _facade.burp_bridge(action, **kwargs)


@mcp.tool()
async def hunter_burp_repeater(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                               body: str = "", tab_name: str = "", http2: bool = True) -> dict:
    """Build a Burp Repeater action descriptor."""
    return _facade.burp_repeater(url, method=method, headers=headers or {}, body=body, tab_name=tab_name, http2=http2)


@mcp.tool()
async def hunter_burp_proxy_search(regex: str, count: int = 50, offset: int = 0) -> dict:
    """Build a Burp proxy history regex-search action descriptor."""
    return _facade.burp_proxy_search(regex, count=count, offset=offset)


@mcp.tool()
async def hunter_burp_scanner_issues(count: int = 50, offset: int = 0, severity_filter: str = "") -> dict:
    """Build a Burp scanner issues retrieval action descriptor."""
    return _facade.burp_scanner_issues(count=count, offset=offset, severity_filter=severity_filter)


@mcp.tool()
async def hunter_burp_collaborator_workflow(workflow: str, url: str, param: str = "", method: str = "GET", template: str = "") -> dict:
    """Build blind SSRF/XXE/CMDI Burp Collaborator workflow plan."""
    return _facade.burp_collaborator_workflow(workflow=workflow, url=url, param=param, method=method, template=template)


@mcp.tool()
async def hunter_tools_healthcheck() -> dict:
    """Check Hunter Tools KB/payload/Burp bridge health."""
    return _facade.health()


@mcp.tool()
async def hunter_tools_capabilities() -> dict:
    """Return Hunter Tools capability matrix."""
    return _facade.capabilities()


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
