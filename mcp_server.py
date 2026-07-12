"""
Hunter Tools v8.2 Complete MCP Server

Exposes the complete Hunter pentest framework under the single hunter_tools MCP server.
Claude is the brain, MCP tools are the hands.

Tools:
- Pipeline: hunter_scan, hunter_recon, hunter_vuln_scan
- Agent: hunter_subdomain, hunter_port_scan, hunter_tech_detect, hunter_dir_enum, hunter_js_analyze
- Payload: hunter_payload_list, hunter_payload_search, hunter_payload_get
- Session: hunter_session_list, hunter_session_status
- Meta: hunter_agents_list, hunter_phases_list, hunter_report
"""

import asyncio
import inspect
import json
import os
import shutil
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

# Ensure hunter package is importable
HUNTER_DIR = Path(__file__).parent
sys.path.insert(0, str(HUNTER_DIR))

from core.result import ok, err, Result
from core.phases import PHASES, PhaseName, PhaseConfig
from core.agents import AGENTS, AgentDefinition
from core.audit import AuditSession
from core.vuln_finding import VulnFinding, SubmissionTier, ProofStrength
from core.vuln_classification import VulnClassification
from core.mcp_server import get_hunter
from core.burp_import import import_burp_evidence
from payloads.loader import PayloadLoader
from core.hunter_tools_facade import HunterToolsFacade
from core.workspace_adapter import OpenTgtyLabWorkspaceAdapter
from core.doctor import HunterDoctor

# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP(
    "hunter_tools",
    instructions="Hunter v8 AI-driven pentest framework. Claude is the brain, MCP tools are the hands. "
    "Use hunter_scan for full pipeline, hunter_recon for recon, individual agents for specific tasks, "
    "and hunter_payload_* for payload knowledge base access.",
)

# Global state
_sessions: Dict[str, AuditSession] = {}
_payload_loader = PayloadLoader(str(HUNTER_DIR / "payloads"))
_hunter = get_hunter()
_hunter_tools = HunterToolsFacade(HUNTER_DIR)
_workspace = OpenTgtyLabWorkspaceAdapter()

def _reset_workspace_adapter(root: Optional[str | Path] = None) -> OpenTgtyLabWorkspaceAdapter:
    """Re-discover workspace after environment/config changes (also useful for tests)."""
    global _workspace
    _workspace = OpenTgtyLabWorkspaceAdapter(root)
    return _workspace
_WORDLIST_ALIASES = {
    "default": "common.txt",
    "common": "common.txt",
    "big": "raft-small.txt",
}
_NUCLEI_TAGS = {
    "sqli-vuln": "sqli",
    "ssrf-vuln": "ssrf",
    "ssti-vuln": "ssti",
    "lfi-vuln": "lfi",
    "rce-vuln": "rce",
    "jwt-vuln": "jwt",
    "upload-vuln": "file-upload",
    "xxe-vuln": "xxe",
    "deser-vuln": "deserialization",
    "cors-vuln": "cors",
    "idor-vuln": "idor",
    "info-leak": "exposure,config,logs",
    "sqli-exploit": "sqli",
    "ssrf-exploit": "ssrf",
    "ssti-exploit": "ssti",
    "lfi-exploit": "lfi",
    "rce-exploit": "rce",
    "jwt-exploit": "jwt",
    "upload-exploit": "file-upload",
    "xxe-exploit": "xxe",
    "deser-exploit": "deserialization",
    "idor-exploit": "idor",
    "chain-exploit": "takeover,workflow,exposure",
}
_LEAD_ONLY_AGENTS = {
    "subdomain",
    "port-scan",
    "tech-detect",
    "dns-info",
    "js-analyze",
    "dir-enum",
    "api-discover",
    "param-discover",
    "auth-analysis",
    "endpoint-map",
    "evidence-collect",
    "cvss-score",
    "report-generate",
    "compliance-check",
}


def _normalize_host(target: str) -> str:
    value = (target or "").strip()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path
    value = value.split("/")[0].strip()
    if ":" in value and value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value


def _normalize_url(target: str) -> str:
    value = (target or "").strip()
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{_normalize_host(value)}"


def _resolve_wordlist(wordlist: str) -> str:
    if not wordlist:
        wordlist = "default"

    alias = _WORDLIST_ALIASES.get(wordlist, wordlist)
    candidate = Path(alias)
    if candidate.exists():
        return str(candidate)

    bundled = HUNTER_DIR / "wordlists" / alias
    if bundled.exists():
        return str(bundled)

    return str(HUNTER_DIR / "wordlists" / "common.txt")


def _nonempty_lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _dedupe(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))


def _parse_json_lines(text: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for line in _nonempty_lines(text):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
            records.extend(item for item in data["results"] if isinstance(item, dict))
        elif isinstance(data, dict):
            records.append(data)
    return records


def _tool_payload(
    tool: str,
    raw: Dict[str, Any],
    parsed: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "tool": tool,
        "status": raw.get("status", "error"),
        "returncode": raw.get("returncode"),
        "stdout_preview": raw.get("stdout", "")[:4000],
        "stderr_preview": raw.get("stderr", "")[:1500],
    }
    if parsed:
        payload.update(parsed)
    if extra:
        payload.update(extra)
    return payload


def _sanitize_target_for_files(target: str) -> str:
    host = _normalize_host(target)
    return "".join(char if char.isalnum() else "_" for char in host).strip("_") or "target"


def _discover_evidence_attachments(
    agent_name: str,
    target: str,
    evidence_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    directory = evidence_dir or (HUNTER_DIR / "evidence" / "tool_output")
    if not directory.exists():
        return {
            "output_files": [],
            "request_file": "",
            "response_file": "",
            "screenshot_files": [],
            "evidence_files": [],
        }

    target_key = _sanitize_target_for_files(target).lower()
    agent_key = (agent_name or "").lower()
    matched: List[str] = []
    for file in directory.iterdir():
        if not file.is_file():
            continue
        name = file.name.lower()
        if agent_key in name and target_key in name:
            matched.append(str(file))

    request_file = next((path for path in matched if "request" in Path(path).name.lower()), "")
    response_file = next((path for path in matched if "response" in Path(path).name.lower()), "")
    screenshot_files = [
        path for path in matched
        if Path(path).suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"} or "screenshot" in Path(path).name.lower()
    ]
    evidence_files = [
        path for path in matched
        if path not in screenshot_files and path not in {request_file, response_file}
    ]
    return {
        "output_files": matched,
        "request_file": request_file,
        "response_file": response_file,
        "screenshot_files": screenshot_files,
        "evidence_files": evidence_files,
    }


def _build_submission_metadata(agent_name: str, execution: Dict[str, Any]) -> Dict[str, Any]:
    status = execution.get("status", "error")
    success = status == "success"
    title = execution.get("display_name") or agent_name

    metadata = {
        "submission_tier": SubmissionTier.LEAD.value,
        "reportable": False,
        "lead_only": True,
        "proof_strength": ProofStrength.NONE.value if not success else ProofStrength.WEAK.value,
        "why_not_reportable": "当前结果属于自动化发现线索，缺少稳定复现和业务影响证明。",
        "review_notes": "默认按 SRC 严审模式降为线索，需人工进一步验证。",
        "business_impact": "",
        "impact_scope": execution.get("target", ""),
        "lead_reason": "自动化资产/漏洞线索默认不直接进入正式报告。",
        "src_score": 10.0 if success else 0.0,
    }

    if agent_name in _LEAD_ONLY_AGENTS:
        return metadata

    if status == "timeout":
        metadata["why_not_reportable"] = execution.get("message", "执行超时，缺少验证结果。")
        metadata["lead_reason"] = metadata["why_not_reportable"]
        metadata["proof_strength"] = ProofStrength.NONE.value
        metadata["src_score"] = 0.0
        return metadata

    if execution.get("count", 0) or execution.get("findings"):
        metadata["proof_strength"] = ProofStrength.WEAK.value
        metadata["src_score"] = 20.0 if success else 5.0
        metadata["why_not_reportable"] = "扫描器命中或异常回显不足以直接进入正式漏洞报告。"
        metadata["lead_reason"] = metadata["why_not_reportable"]

    return metadata


def _result_to_report_item(result: Dict[str, Any]) -> Dict[str, Any]:
    output_files = result.get("output_files", [])
    request_file = result.get("request_file", "")
    response_file = result.get("response_file", "")
    screenshot_files = result.get("screenshot_files", [])
    evidence_files = result.get("evidence_files", [])

    if output_files:
        if not request_file:
            request_file = next((path for path in output_files if "request" in Path(path).name.lower()), "")
        if not response_file:
            response_file = next((path for path in output_files if "response" in Path(path).name.lower()), "")
        if not screenshot_files:
            screenshot_files = [
                path for path in output_files
                if Path(path).suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"} or "screenshot" in Path(path).name.lower()
            ]
        if not evidence_files:
            evidence_files = [
                path for path in output_files
                if path not in screenshot_files and path not in {request_file, response_file}
            ]

    return {
        "id": result.get("agent", ""),
        "title": result.get("display_name", result.get("agent", "Hunter Finding")),
        "vuln_type": result.get("agent", ""),
        "submission_tier": result.get("submission_tier", SubmissionTier.LEAD.value),
        "reportable": result.get("reportable", False),
        "proof_strength": result.get("proof_strength", ProofStrength.NONE.value),
        "impact_scope": result.get("impact_scope", result.get("target", "")),
        "business_impact": result.get("business_impact", ""),
        "why_not_reportable": result.get("why_not_reportable", ""),
        "lead_reason": result.get("lead_reason", ""),
        "review_notes": result.get("review_notes", ""),
        "evidence": result.get("stdout_preview", "") or result.get("message", ""),
        "request": result.get("request", ""),
        "response": result.get("response", ""),
        "request_file": request_file,
        "response_file": response_file,
        "screenshot_files": screenshot_files,
        "evidence_files": evidence_files,
        "remediation": result.get("remediation", ""),
        "actual_result": result.get("actual_result", ""),
    }


def _render_markdown_report(session: AuditSession, style: str = "cn-src") -> str:
    report = session.export_report_json()
    from core.report_templates import render_cn_src_report, render_hackerone_report

    reportable = report.get("reportable_findings", [])
    lead_count = len(report.get("lead_findings", []))
    if style == "hackerone":
        return render_hackerone_report(report["target"], reportable, lead_count)
    if style == "butian":
        return render_cn_src_report(report["target"], reportable, lead_count, platform="butian")
    if style == "vulbox":
        return render_cn_src_report(report["target"], reportable, lead_count, platform="vulbox")
    return render_cn_src_report(report["target"], reportable, lead_count, platform="generic-src")


def _dns_lookup(host: str) -> Dict[str, Any]:
    try:
        infos = socket.getaddrinfo(host, None)
        addresses = _dedupe([item[4][0] for item in infos if item and item[4]])
        return {
            "tool": "socket.getaddrinfo",
            "status": "success",
            "host": host,
            "addresses": addresses,
            "count": len(addresses),
        }
    except Exception as exc:
        return {
            "tool": "socket.getaddrinfo",
            "status": "error",
            "host": host,
            "error": str(exc),
        }


def _execute_agent(agent_name: str, target: str, **kwargs) -> Dict[str, Any]:
    host = _normalize_host(target)
    url = _normalize_url(target)

    if agent_name == "subdomain":
        raw = _hunter.subfinder_enum(host)
        subdomains = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("subfinder", raw, {
            "target": host,
            "subdomains": subdomains,
            "count": len(subdomains),
        })

    if agent_name == "port-scan":
        ports = kwargs.get("ports", "top-1000")
        raw = _hunter.naabu_scan(host, ports=ports)
        entries = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("naabu", raw, {
            "target": host,
            "ports": ports,
            "open_ports": entries,
            "count": len(entries),
        })

    if agent_name == "tech-detect":
        probe_raw = _hunter.httpx_probe(url)
        tech_raw = _hunter.whatweb_identify(url)
        status = "success" if "success" in {probe_raw.get("status"), tech_raw.get("status")} else "error"
        return {
            "status": status,
            "target": url,
            "http_probe": _tool_payload("httpx", probe_raw, {
                "services": _dedupe(_nonempty_lines(probe_raw.get("stdout", ""))),
            }),
            "fingerprint": _tool_payload("whatweb", tech_raw, {
                "matches": _dedupe(_nonempty_lines(tech_raw.get("stdout", ""))),
            }),
        }

    if agent_name == "dns-info":
        return _dns_lookup(host)

    if agent_name == "dir-enum":
        wordlist = _resolve_wordlist(kwargs.get("wordlist", "default"))
        raw = _hunter.ffuf_fuzz(url, wordlist=wordlist)
        records = _parse_json_lines(raw.get("stdout", ""))
        return _tool_payload("ffuf", raw, {
            "target": url,
            "wordlist": wordlist,
            "results": records[:200],
            "count": len(records),
        })

    if agent_name == "js-analyze":
        js_raw = _hunter.js_analyze(url)
        crawl_raw = _hunter.katana_crawl(url)
        wayback_raw = _hunter.gau_urls(host)
        return {
            "status": "success" if "success" in {js_raw.get("status"), crawl_raw.get("status"), wayback_raw.get("status")} else "error",
            "target": url,
            "javascript": _tool_payload("getjs", js_raw, {
                "urls": _dedupe(_nonempty_lines(js_raw.get("stdout", "")))[:200],
            }),
            "crawler": _tool_payload("katana", crawl_raw, {
                "endpoints": _dedupe(_nonempty_lines(crawl_raw.get("stdout", "")))[:400],
            }),
            "archives": _tool_payload("gau", wayback_raw, {
                "urls": _dedupe(_nonempty_lines(wayback_raw.get("stdout", "")))[:400],
            }),
        }

    if agent_name in {"api-discover", "param-discover", "endpoint-map"}:
        crawl_raw = _hunter.katana_crawl(url)
        wayback_raw = _hunter.gau_urls(host)
        js_raw = _hunter.js_analyze(url)
        combined = _dedupe(
            _nonempty_lines(crawl_raw.get("stdout", ""))
            + _nonempty_lines(wayback_raw.get("stdout", ""))
            + _nonempty_lines(js_raw.get("stdout", ""))
        )
        return {
            "status": "success" if "success" in {crawl_raw.get("status"), wayback_raw.get("status"), js_raw.get("status")} else "error",
            "target": url,
            "count": len(combined),
            "endpoints": combined[:500],
            "sources": {
                "katana": _tool_payload("katana", crawl_raw),
                "gau": _tool_payload("gau", wayback_raw),
                "getjs": _tool_payload("getjs", js_raw),
            },
        }

    if agent_name == "auth-analysis":
        probe_raw = _hunter.httpx_probe(url)
        waf_raw = _hunter.waf_detect(url)
        return {
            "status": "success" if "success" in {probe_raw.get("status"), waf_raw.get("status")} else "error",
            "target": url,
            "probe": _tool_payload("httpx", probe_raw, {
                "services": _dedupe(_nonempty_lines(probe_raw.get("stdout", ""))),
            }),
            "waf": _tool_payload("wafw00f", waf_raw, {
                "detections": _dedupe(_nonempty_lines(waf_raw.get("stdout", ""))),
            }),
        }

    if agent_name == "xss-vuln" or agent_name == "xss-exploit":
        raw = _hunter.dalfox_xss(url)
        findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("dalfox", raw, {
            "target": url,
            "findings": findings[:200],
            "count": len(findings),
        })

    if agent_name == "sqli-vuln" or agent_name == "sqli-exploit":
        if "?" in url:
            raw = _hunter.sqlmap_test(url, level=2, risk=2)
            findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
            return _tool_payload("sqlmap", raw, {
                "target": url,
                "findings": findings[:200],
                "count": len(findings),
            })
        raw = _hunter.nuclei_scan(url, tags="sqli")
        findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("nuclei", raw, {
            "target": url,
            "findings": findings[:200],
            "count": len(findings),
        })

    if agent_name in _NUCLEI_TAGS:
        raw = _hunter.nuclei_scan(url, tags=_NUCLEI_TAGS[agent_name])
        findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("nuclei", raw, {
            "target": url,
            "tags": _NUCLEI_TAGS[agent_name],
            "findings": findings[:200],
            "count": len(findings),
        })

    if agent_name == "evidence-collect":
        return {
            "status": "success",
            "message": "Evidence is retained in the session audit log and tool output directory.",
            "output_dir": str(HUNTER_DIR / "evidence" / "tool_output"),
        }

    if agent_name == "cvss-score":
        return {
            "status": "success",
            "message": "CVSS scoring requires manual analyst review after automated findings are collected.",
        }

    if agent_name == "report-generate":
        return {
            "status": "success",
            "message": "Use hunter_report with the session_id to export markdown or JSON results.",
        }

    if agent_name == "compliance-check":
        return {
            "status": "success",
            "message": "Compliance review is analyst-driven; no automatic policy pack is bundled yet.",
        }

    return {
        "status": "error",
        "message": f"No execution mapping defined for agent '{agent_name}'.",
    }


async def _execute_agent_async(agent_name: str, target: str, **kwargs) -> Dict[str, Any]:
    timeout = kwargs.pop("timeout", None)
    if timeout is None:
        timeout = 150 if agent_name in {"js-analyze", "api-discover", "param-discover", "endpoint-map"} else 90
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_execute_agent, agent_name, target, **kwargs),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return {
            "status": "timeout",
            "message": f"Agent '{agent_name}' timed out after {timeout}s.",
            "target": target,
        }


# ============================================================
# Pipeline Tools
# ============================================================

@mcp.tool()
async def hunter_scan(
    target: str,
    mode: str = "standard",
    phases: Optional[List[str]] = None,
) -> str:
    """
    Run full pentest pipeline on target.

    Args:
        target: Target domain or IP (e.g. "example.com")
        mode: Scan intensity - "quick" (5min), "standard" (30min), "aggressive" (60min+)
        phases: Specific phases to run. Default: all 5 phases.
                Options: ["pre-recon", "recon", "vulnerability-analysis", "exploitation", "reporting"]

    Returns:
        JSON with session_id, findings, and summary.
    """
    session_id = f"hunter-{int(time.time())}"
    session = AuditSession(session_id, target)
    _sessions[session_id] = session

    session.log_event("scan_start", {"target": target, "mode": mode})

    if phases is None:
        phase_names = [p.value for p in PhaseName]
    else:
        phase_names = phases

    # Build agent list from selected phases
    agents_to_run = []
    for phase_name in phase_names:
        try:
            pn = PhaseName(phase_name)
            config = PHASES[pn]
            agents_to_run.extend(config.agents)
        except (ValueError, KeyError):
            return json.dumps({"error": f"Unknown phase: {phase_name}"})

    # Execute agents through the local tool runner
    results = []
    for agent_name in agents_to_run:
        agent_def = AGENTS.get(agent_name)
        if not agent_def:
            continue

        session.log_agent_start(agent_name)
        start = time.time()
        execution = await _execute_agent_async(agent_name, target, mode=mode)
        execution.update(_discover_evidence_attachments(agent_name, target))
        execution.update(_build_submission_metadata(agent_name, execution))
        result = {
            "agent": agent_name,
            "display_name": agent_def.display_name,
            **execution,
        }
        results.append(result)

        duration = time.time() - start
        session.log_agent_end(agent_name, execution.get("status") != "error", duration)

    session.log_event("scan_complete", {
        "target": target,
        "agents_run": len(results),
        "mode": mode,
    })
    reportable_findings = [_result_to_report_item(item) for item in results if item.get("reportable")]
    lead_findings = [_result_to_report_item(item) for item in results if not item.get("reportable")]
    summary = {
        "total": len(results),
        "reportable_count": len(reportable_findings),
        "lead_count": len(lead_findings),
        "mode": mode,
    }
    session.set_report_data(reportable_findings=reportable_findings, lead_findings=lead_findings, summary=summary)

    output = {
        "session_id": session_id,
        "target": target,
        "mode": mode,
        "phases": phase_names,
        "agents_run": len(results),
        "results": results,
        "status": "complete",
        "reportable_findings": reportable_findings,
        "lead_findings": lead_findings,
        "summary": summary,
        "note": "Executed through the local Hunter tool runner (subfinder/httpx/naabu/ffuf/nuclei/sqlmap/dalfox/etc.).",
    }

    return json.dumps(output, indent=2, ensure_ascii=False)


@mcp.tool()
async def hunter_recon(target: str) -> str:
    """
    Run recon-only scan (pre-recon + recon phases).
    Subdomain enum, port scan, tech detect, dir enum, API discovery.

    Args:
        target: Target domain or IP

    Returns:
        JSON with recon results.
    """
    return await hunter_scan(target, mode="quick", phases=["pre-recon", "recon"])


@mcp.tool()
async def hunter_vuln_scan(target: str) -> str:
    """
    Run vulnerability analysis (pre-recon + recon + vuln-analysis).
    Full recon + 13 vulnerability type checks.

    Args:
        target: Target domain or IP

    Returns:
        JSON with vulnerability scan results.
    """
    return await hunter_scan(
        target,
        mode="standard",
        phases=["pre-recon", "recon", "vulnerability-analysis"],
    )


# ============================================================
# Individual Agent Tools
# ============================================================

async def _run_single_agent(agent_name: str, target: str, **kwargs) -> str:
    """Run a single agent and return results."""
    agent_def = AGENTS.get(agent_name)
    if not agent_def:
        return json.dumps({"error": f"Unknown agent: {agent_name}"})

    session_id = f"hunter-{agent_name}-{int(time.time())}"
    session = AuditSession(session_id, target)
    _sessions[session_id] = session

    session.log_agent_start(agent_name)
    start = time.time()

    execution = await _execute_agent_async(agent_name, target, **kwargs)
    execution.update(_discover_evidence_attachments(agent_name, target))
    execution.update(_build_submission_metadata(agent_name, execution))
    result = {
        "session_id": session_id,
        "agent": agent_name,
        "display_name": agent_def.display_name,
        "description": agent_def.description,
        "target": target,
        "model_tier": agent_def.model_tier.value,
        "tools_required": agent_def.tools_required,
        "payload_types": agent_def.payload_types,
        **kwargs,
        **execution,
    }
    session.set_report_data(
        reportable_findings=[_result_to_report_item(result)] if result.get("reportable") else [],
        lead_findings=[_result_to_report_item(result)] if not result.get("reportable") else [],
        summary={
            "total": 1,
            "reportable_count": 1 if result.get("reportable") else 0,
            "lead_count": 0 if result.get("reportable") else 1,
        },
    )

    duration = time.time() - start
    session.log_agent_end(agent_name, execution.get("status") != "error", duration)

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
async def hunter_subdomain(target: str) -> str:
    """
    Enumerate subdomains for target (crt.sh + DNS brute).

    Args:
        target: Target domain (e.g. "example.com")

    Returns:
        JSON with discovered subdomains.
    """
    return await _run_single_agent("subdomain", target)


@mcp.tool()
async def hunter_port_scan(target: str, ports: str = "top-1000") -> str:
    """
    Scan target ports.

    Args:
        target: Target IP or domain
        ports: Port range - "top-1000", "top-100", "full", or custom like "80,443,8080"

    Returns:
        JSON with open ports and services.
    """
    return await _run_single_agent("port-scan", target, ports=ports)


@mcp.tool()
async def hunter_tech_detect(target: str) -> str:
    """
    Detect target technology stack (framework, language, server, CMS).

    Args:
        target: Target URL or domain

    Returns:
        JSON with detected technologies.
    """
    return await _run_single_agent("tech-detect", target)


@mcp.tool()
async def hunter_dir_enum(target: str, wordlist: str = "default") -> str:
    """
    Enumerate directories and files on target.

    Args:
        target: Target URL (e.g. "https://example.com")
        wordlist: Wordlist to use - "default", "common", "big", or path to custom wordlist

    Returns:
        JSON with discovered directories and files.
    """
    return await _run_single_agent("dir-enum", target, wordlist=wordlist)


@mcp.tool()
async def hunter_js_analyze(target: str) -> str:
    """
    Analyze JavaScript files for endpoints, secrets, internal URLs.

    Args:
        target: Target URL

    Returns:
        JSON with extracted endpoints, API keys, internal URLs.
    """
    return await _run_single_agent("js-analyze", target)


# ============================================================
# Auto-* Direct Tools (v8 hardened)
# ============================================================


def _json_dumps(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _call_with_supported_kwargs(func, *args, **kwargs):
    """Call func while filtering kwargs unsupported by older scanner impls."""
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return func(*args, **kwargs)

    has_var_kwargs = any(
        param.kind == inspect.Parameter.VAR_KEYWORD
        for param in signature.parameters.values()
    )
    if has_var_kwargs:
        return func(*args, **kwargs)

    supported = {
        key: value
        for key, value in kwargs.items()
        if key in signature.parameters
    }
    return func(*args, **supported)


async def _safe_json_tool(tool_name: str, func, *args, timeout: int = 120, **kwargs) -> str:
    """Run a blocking scanner implementation without leaking exceptions to MCP."""
    start = time.time()
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_call_with_supported_kwargs, func, *args, **kwargs),
            timeout=timeout,
        )
        if not isinstance(result, dict):
            result = {"result": result}
        result.setdefault("status", "success")
        result.setdefault("tool", tool_name)
        result["elapsed_seconds"] = round(time.time() - start, 3)
        return _json_dumps(result)
    except asyncio.TimeoutError:
        return _json_dumps({
            "status": "timeout",
            "tool": tool_name,
            "elapsed_seconds": round(time.time() - start, 3),
            "error": f"{tool_name} timed out after {timeout}s",
        })
    except Exception as exc:
        return _json_dumps({
            "status": "error",
            "tool": tool_name,
            "elapsed_seconds": round(time.time() - start, 3),
            "error": str(exc),
            "error_type": type(exc).__name__,
        })


def _join_endpoint(target: str, endpoint: str = "") -> str:
    if not endpoint:
        return target
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    return target.rstrip("/") + "/" + endpoint.lstrip("/")


@mcp.tool()
async def hunter_auto_sqli(target: str, param: str = "category", method: str = "GET") -> str:
    """Automated SQL injection scanner."""
    from core.auto_sqli import auto_sqli_impl
    return await _safe_json_tool("hunter_auto_sqli", auto_sqli_impl, target, param=param, method=method)


@mcp.tool()
async def hunter_auto_xss(target: str, param: str = "q", method: str = "GET") -> str:
    """Automated XSS scanner."""
    from core.auto_xss import auto_xss_impl
    return await _safe_json_tool("hunter_auto_xss", auto_xss_impl, target, param=param, method=method)


@mcp.tool()
async def hunter_auto_ssrf(target: str, param: str = "url", method: str = "GET", collaborator: str = "") -> str:
    """Automated SSRF scanner."""
    from core.auto_ssrf import auto_ssrf_impl
    return await _safe_json_tool(
        "hunter_auto_ssrf",
        auto_ssrf_impl,
        target,
        param=param,
        method=method,
        collaborator=collaborator,
    )


@mcp.tool()
async def hunter_auto_xxe(target: str, param: str = "", method: str = "POST", collaborator: str = "") -> str:
    """Automated XXE scanner."""
    from core.auto_xxe import auto_xxe_impl
    return await _safe_json_tool(
        "hunter_auto_xxe",
        auto_xxe_impl,
        target,
        param=param,
        method=method,
        oob_domain=collaborator,
        collaborator=collaborator,
    )


@mcp.tool()
async def hunter_auto_csrf(target: str, cookie: str = "") -> str:
    """Automated CSRF vulnerability detection and exploit generation."""
    from core.auto_csrf import scan
    return await _safe_json_tool("hunter_auto_csrf", scan, target, cookie=cookie)


@mcp.tool()
async def hunter_auto_graphql(target: str) -> str:
    """Automated GraphQL vulnerability scanner."""
    from core.auto_graphql import full_scan
    return await _safe_json_tool("hunter_auto_graphql", full_scan, target)


@mcp.tool()
async def hunter_auto_websocket(target: str) -> str:
    """Automated WebSocket vulnerability scanner."""
    from core.auto_websocket import full_scan
    return await _safe_json_tool("hunter_auto_websocket", full_scan, target)


@mcp.tool()
async def hunter_auto_ssti(target: str, param: str = "q", method: str = "GET") -> str:
    """Automated SSTI vulnerability scanner with engine detection."""
    from core.auto_ssti import auto_ssti_impl
    return await _safe_json_tool("hunter_auto_ssti", auto_ssti_impl, target, param=param, method=method)


@mcp.tool()
async def hunter_auto_cmd(target: str, param: str = "cmd", method: str = "GET") -> str:
    """Automated command injection scanner."""
    from core.auto_cmd import auto_cmd_impl
    return await _safe_json_tool("hunter_auto_cmd", auto_cmd_impl, target, param=param, method=method)


@mcp.tool()
async def hunter_auto_idor(target: str, endpoint: str = "", cookie: str = "") -> str:
    """Automated IDOR vulnerability scanner."""
    from core.auto_idor import auto_idor_impl
    url = _join_endpoint(target, endpoint)
    return await _safe_json_tool("hunter_auto_idor", auto_idor_impl, url=url, cookie=cookie)


@mcp.tool()
async def hunter_auto_race(target: str, cookie: str = "") -> str:
    """Automated race-condition scanner."""
    from core.auto_race import full_scan
    return await _safe_json_tool("hunter_auto_race", full_scan, target, session_cookie=cookie, cookie=cookie)


@mcp.tool()
async def hunter_auto_cors(target: str, cookie: str = "") -> str:
    """Automated CORS misconfiguration scanner."""
    from core.auto_cors import scan
    return await _safe_json_tool("hunter_auto_cors", scan, target, cookie=cookie)


@mcp.tool()
async def hunter_auto_jwt(target: str, token: str = "", cookie: str = "") -> str:
    """Automated JWT vulnerability scanner."""
    from core.auto_jwt import AutoJWT

    def _scan():
        jwt = AutoJWT(target, token, cookie)
        return jwt.scan()

    return await _safe_json_tool("hunter_auto_jwt", _scan)


@mcp.tool()
async def hunter_auto_access_control(target: str, cookie: str = "") -> str:
    """Automated access-control scanner."""
    from core.auto_access_control import scan
    return await _safe_json_tool("hunter_auto_access_control", scan, target, cookie=cookie)


@mcp.tool()
async def hunter_unified_scan(target: str, cookie: str = "", collaborator: str = "",
                               phases: Optional[List[str]] = None) -> str:
    """Unified scan engine - runs selected phases automatically."""
    from core.unified_scanner import UnifiedScanner

    def _scan():
        scanner = UnifiedScanner(
            target=target,
            session_cookie=cookie,
            collaborator_domain=collaborator,
        )
        return scanner.run_full_scan(phases=phases)

    return await _safe_json_tool("hunter_unified_scan", _scan, timeout=240)


# ============================================================
# V8 Meta / Orchestration Tools
# ============================================================


def _tool_available(name: str) -> Dict[str, Any]:
    candidates = []
    tools_dir = getattr(_hunter, "tools_dir", None)
    if tools_dir:
        candidates.append(Path(tools_dir) / f"{name}.exe")
    found_path = shutil.which(name) or shutil.which(f"{name}.exe")
    if found_path:
        candidates.append(Path(found_path))
    existing = [str(path) for path in candidates if path and Path(path).exists()]
    return {
        "available": bool(existing),
        "paths": existing,
    }


def _registered_hunter_tools() -> List[str]:
    return sorted(
        name for name, value in globals().items()
        if name.startswith("hunter_") and callable(value)
    )


def _doctor() -> HunterDoctor:
    workspace_root = _workspace.root if _workspace and _workspace.root else None
    return HunterDoctor(
        HUNTER_DIR,
        registered_tools=_registered_hunter_tools(),
        workspace_root=workspace_root,
    )


@mcp.tool()
async def hunter_contract_check() -> str:
    """Validate the machine-readable Hunter/OpenTgtyLab integration contract."""
    return _json_dumps(_doctor().contract_check())


@mcp.tool()
async def hunter_config_audit() -> str:
    """Audit discovered Codex/project MCP configs for legacy hunter registrations."""
    return _json_dumps(_doctor().config_audit())


@mcp.tool()
async def hunter_runtime_status() -> str:
    """Return portable runtime, interpreter, workspace and tool-count diagnostics."""
    return _json_dumps(_doctor().runtime_status())


@mcp.tool()
async def hunter_doctor() -> str:
    """Run contract, configuration and runtime diagnostics in one call."""
    return _json_dumps(_doctor().run())


def _payload_inventory() -> Dict[str, Any]:
    types = _payload_loader.list_types()
    counts = {}
    sections = {}
    for payload_type in types:
        try:
            data = _payload_loader.get_payloads(payload_type)
            counts[payload_type] = len(_payload_loader.get_all_payloads_flat(payload_type))
            sections[payload_type] = sorted(data.keys()) if isinstance(data, dict) else []
        except Exception as exc:
            counts[payload_type] = 0
            sections[payload_type] = [f"error: {exc}"]
    return {
        "types": types,
        "total_types": len(types),
        "counts": counts,
        "sections": sections,
    }


@mcp.tool()
async def hunter_healthcheck() -> str:
    """Check Hunter MCP, payload inventory, wordlists, and external tool availability locally."""
    required_mcp = [
        "hunter_scan", "hunter_recon", "hunter_vuln_scan",
        "hunter_auto_sqli", "hunter_auto_xss", "hunter_auto_ssrf", "hunter_auto_ssti",
        "hunter_auto_cmd", "hunter_auto_xxe", "hunter_auto_idor", "hunter_auto_csrf",
        "hunter_auto_cors", "hunter_auto_jwt", "hunter_auto_graphql", "hunter_auto_websocket",
        "hunter_auto_race", "hunter_auto_access_control", "hunter_unified_scan",
        "hunter_healthcheck", "hunter_capabilities", "hunter_recommend_next",
        "hunter_kb_list", "hunter_kb_search", "hunter_kb_read", "hunter_kb_recommend",
        "hunter_burp_bridge", "hunter_burp_repeater", "hunter_burp_proxy_search",
        "hunter_burp_scanner_issues", "hunter_burp_collaborator_workflow",
    ]
    registered = _registered_hunter_tools()
    missing_mcp = [name for name in required_mcp if name not in registered]
    external_names = [
        "nuclei", "subfinder", "naabu", "httpx", "ffuf", "katana", "gau",
        "dalfox", "sqlmap", "wafw00f", "whatweb", "getjs",
    ]
    external = {name: _tool_available(name) for name in external_names}
    wordlists = {
        alias: {
            "path": _resolve_wordlist(alias),
            "exists": Path(_resolve_wordlist(alias)).exists(),
        }
        for alias in sorted(_WORDLIST_ALIASES)
    }
    payloads = _payload_inventory()
    degraded = missing_mcp or any(not info["available"] for info in external.values())
    return _json_dumps({
        "framework": "Hunter",
        "version": "v8-hardening",
        "status": "degraded" if degraded else "ok",
        "base_dir": str(HUNTER_DIR),
        "mcp_tools": {
            "registered": registered,
            "required": required_mcp,
            "missing": missing_mcp,
            "total_registered": len(registered),
        },
        "external_tools": external,
        "wordlists": wordlists,
        "payloads": payloads,
        "hunter_tools": _hunter_tools.health().get("data", {}),
        "workspace": _workspace.health().get("data", {}),
        "integration_v2": _doctor().run()["data"]["checks"],
        "notes": [
            "网络型扫描依赖外部 CLI；缺失时仍可使用 payload/meta/report 工具。",
            "所有 auto 工具经 safe wrapper 返回 JSON，不应把异常泄漏到 MCP 层。",
        ],
    })


@mcp.tool()
async def hunter_capabilities() -> str:
    """Return the actual Hunter MCP capability matrix for agent-side routing."""
    registered = set(_registered_hunter_tools())
    definitions = {
        "hunter_recon": ("pipeline", "Recon pipeline"),
        "hunter_vuln_scan": ("pipeline", "Recon + vulnerability-analysis pipeline"),
        "hunter_scan": ("pipeline", "Configurable full pipeline"),
        "hunter_subdomain": ("recon", "Subdomain enumeration"),
        "hunter_port_scan": ("recon", "Port scanning"),
        "hunter_tech_detect": ("recon", "Technology fingerprinting"),
        "hunter_dir_enum": ("recon", "Directory/path enumeration"),
        "hunter_js_analyze": ("recon", "JavaScript and endpoint extraction"),
        "hunter_auto_sqli": ("auto-vuln", "SQL injection checks"),
        "hunter_auto_xss": ("auto-vuln", "XSS checks"),
        "hunter_auto_ssrf": ("auto-vuln", "SSRF checks"),
        "hunter_auto_ssti": ("auto-vuln", "SSTI checks"),
        "hunter_auto_cmd": ("auto-vuln", "Command injection checks"),
        "hunter_auto_xxe": ("auto-vuln", "XXE checks"),
        "hunter_auto_idor": ("auto-vuln", "IDOR checks"),
        "hunter_auto_csrf": ("auto-vuln", "CSRF checks"),
        "hunter_auto_cors": ("auto-vuln", "CORS checks"),
        "hunter_auto_jwt": ("auto-vuln", "JWT checks"),
        "hunter_auto_graphql": ("auto-vuln", "GraphQL checks"),
        "hunter_auto_websocket": ("auto-vuln", "WebSocket checks"),
        "hunter_auto_race": ("auto-vuln", "Race-condition checks"),
        "hunter_auto_access_control": ("auto-vuln", "Access-control checks"),
        "hunter_unified_scan": ("orchestration", "Selected multi-phase scan"),
        "hunter_payload_list": ("payload", "List payload types"),
        "hunter_payload_search": ("payload", "Search payload KB"),
        "hunter_payload_get": ("payload", "Read payload type or section"),
        "hunter_payload_generate": ("payload", "Generate templated payloads"),
        "hunter_burp_import": ("evidence", "Import Burp evidence"),
        "hunter_session_list": ("session", "List sessions"),
        "hunter_session_status": ("session", "Inspect session"),
        "hunter_report": ("report", "Generate report"),
        "hunter_agents_list": ("meta", "List agents"),
        "hunter_phases_list": ("meta", "List phases"),
        "hunter_healthcheck": ("meta", "Runtime health check"),
        "hunter_capabilities": ("meta", "Capability matrix"),
        "hunter_recommend_next": ("meta", "Evidence-driven next-step routing"),
        "hunter_kb_list": ("kb", "List Hunter technique markdown and payload YAML inventory"),
        "hunter_kb_search": ("kb", "Search Hunter KB by signal/query"),
        "hunter_kb_read": ("kb", "Read exact Hunter KB file under payloads/"),
        "hunter_kb_recommend": ("kb", "Recommend KB, payload, Hunter tools and Burp proof actions"),
        "hunter_burp_bridge": ("burp-bridge", "Generic Burp MCP action descriptor builder"),
        "hunter_burp_repeater": ("burp-bridge", "Build a Burp Repeater action descriptor"),
        "hunter_burp_proxy_search": ("burp-bridge", "Build a Proxy history regex search action"),
        "hunter_burp_scanner_issues": ("burp-bridge", "Build a Scanner issues retrieval action"),
        "hunter_burp_collaborator_workflow": ("burp-bridge", "Build SSRF/XXE/CMDI Collaborator workflow plan"),
        "hunter_workspace_health": ("workspace", "Check OpenTgtyLab workspace integration"),
        "hunter_case_open": ("workspace", "Read a case state.json"),
        "hunter_case_status": ("workspace", "Read compact case status"),
        "hunter_case_update": ("workspace", "Atomically update controlled case state fields"),
        "hunter_case_next_steps": ("workspace", "Read case next_steps"),
        "hunter_project_kb_search": ("workspace-kb", "Search OpenTgtyLab project KB"),
        "hunter_project_kb_read": ("workspace-kb", "Read an exact project KB technique"),
        "hunter_evidence_save": ("workspace-artifact", "Save case evidence under exports"),
        "hunter_note_write": ("workspace-artifact", "Write a project note under exports/notes"),
        "hunter_report_publish": ("workspace-artifact", "Publish a report under exports/reports"),
        "hunter_workspace_recommend": ("workspace", "Combine case state, project KB and Hunter routing"),
        "hunter_doctor": ("diagnostics", "Aggregate Integration v2 diagnostics"),
        "hunter_config_audit": ("diagnostics", "Audit MCP configuration registrations"),
        "hunter_runtime_status": ("diagnostics", "Inspect portable runtime state"),
        "hunter_contract_check": ("diagnostics", "Validate the machine-readable integration contract"),
    }
    tools = {
        name: {
            "category": category,
            "description": description,
            "available": name in registered,
        }
        for name, (category, description) in sorted(definitions.items())
    }
    return _json_dumps({
        "framework": "Hunter",
        "version": "v8-hardening",
        "tools": tools,
        "payloads": _payload_inventory(),
        "hunter_tools": _hunter_tools.capabilities().get("data", {}),
        "workspace": _workspace.health().get("data", {}),
        "integration_contract": _doctor().contract_check().get("data", {}),
        "recommended_workflow": [
            "hunter_healthcheck",
            "hunter_capabilities",
            "targeted recon via hunter_recon / atomics",
            "hunter_recommend_next based on observed signals",
            "targeted auto_* proof collection",
            "hunter_burp_import / hunter_report for evidence packaging",
        ],
        "selection_rule": "Prefer targeted proof tools over blind broad scans; report only findings with reproducible impact.",
    })


@mcp.tool()
async def hunter_recommend_next(target: str = "", signals: Optional[List[str]] = None, finding: str = "", case_slug: str = "") -> str:
    """Recommend next Hunter tools from observed signals/findings."""
    raw = " ".join((signals or []) + [finding or ""]).lower()
    recommendations: List[Dict[str, Any]] = []

    def add(tool: str, reason: str, proof_goal: str, priority: int):
        if any(item["tool"] == tool for item in recommendations):
            return
        recommendations.append({
            "tool": tool,
            "priority": priority,
            "reason": reason,
            "proof_goal": proof_goal,
        })

    if any(token in raw for token in ["idor", "user_id", "userid", "uid", "object", "越权", "x-id-token", "authorization"]):
        add("hunter_auto_idor", "ID/对象/token 信号提示可能存在直接对象引用或横向越权。", "用两个授权身份或 ID 差分证明可读取/修改非本人数据。", 10)
        add("hunter_auto_access_control", "认证/角色/对象信号需要访问控制矩阵验证。", "对比无 token、低权 token、高权 token 的状态码与敏感字段差异。", 9)
    if any(token in raw for token in ["jwt", "token", "idtoken", "secret", "hs256", "hs512", "kid"]):
        add("hunter_auto_jwt", "发现 JWT/token/secret 信号，应验证算法、kid、弱密钥和服务端信任边界。", "只用授权测试账号验证后端是否接受伪造/篡改 token。", 8)
    if "cors" in raw or "origin" in raw or "access-control" in raw:
        add("hunter_auto_cors", "CORS/Origin 信号需要确认是否能跨域读取受保护数据。", "证明 ACAO/ACAC 与凭据模式组合能读到敏感响应，而不只是配置异常。", 7)
    if "graphql" in raw or "introspection" in raw:
        add("hunter_auto_graphql", "GraphQL 信号需要 schema、权限和批量/深度限制验证。", "证明 introspection/private query 可访问敏感字段或绕过授权。", 7)
    if "websocket" in raw or "ws://" in raw or "wss://" in raw:
        add("hunter_auto_websocket", "WebSocket 信号需要 Origin、鉴权和消息篡改验证。", "证明跨站连接或消息篡改能读取/执行受保护动作。", 6)
    if any(token in raw for token in ["csrf", "form", "state-changing", "referer"]):
        add("hunter_auto_csrf", "表单/状态变更/Referer 信号提示 CSRF 或流程绕过。", "生成最小 PoC 并证明授权用户状态发生可重复变化。", 6)
    if any(token in raw for token in ["sqli", "sql", "mysql", "oracle", "postgres", "error near", "union"]):
        add("hunter_auto_sqli", "SQL/数据库错误信号需要注入确认。", "提取数据库 banner 或低敏证明数据，避免只报报错。", 5)
    if any(token in raw for token in ["xss", "script", "dom", "innerhtml", "reflect"]):
        add("hunter_auto_xss", "反射/DOM sink 信号需要上下文化 XSS 验证。", "证明 payload 在浏览器运行态执行，保存 request/response/screenshot。", 5)
    if any(token in raw for token in ["ssrf", "url=", "callback", "metadata", "169.254"]):
        add("hunter_auto_ssrf", "URL/callback/metadata 信号需要 SSRF 路径验证。", "证明服务端发起请求或可访问授权内网资源。", 5)
    if any(token in raw for token in ["xml", "xxe", "svg", "doctype"]):
        add("hunter_auto_xxe", "XML/SVG/DOCTYPE 信号需要 XXE/XInclude 验证。", "证明文件读取或 OOB 回连，不只证明解析 XML。", 5)
    if any(token in raw for token in ["ssti", "template", "jinja", "freemarker", "thymeleaf"]):
        add("hunter_auto_ssti", "模板语法/报错信号需要 SSTI 引擎识别。", "证明表达式执行结果或受控命令输出。", 5)
    if any(token in raw for token in ["cmd", "command", "ping", "whoami", "shell"]):
        add("hunter_auto_cmd", "命令参数/系统调用信号需要命令注入验证。", "证明可控命令结果或 OOB 回连。", 5)
    if any(token in raw for token in ["race", "coupon", "payment", "balance", "concurrent", "并发", "竞态"]):
        add("hunter_auto_race", "支付/优惠/余额/并发信号优先验证竞态和重放。", "证明并发导致一次以上的授权外状态变化。", 8)
    if any(token in raw for token in ["swagger", "openapi", "api-docs", "js", "endpoint"]):
        add("hunter_js_analyze", "API 文档或 JS 暴露信号应先扩展端点图。", "提取端点、参数、token 使用点，转入针对性 proof。", 4)

    if not recommendations:
        add("hunter_recon", "缺少明确漏洞信号，先做低噪侦察建立资产/端点基线。", "获得存活服务、技术栈、JS/API 端点后再选择 auto_*。", 1)

    recommendations.sort(key=lambda item: item["priority"], reverse=True)
    hunter_tools_rec = _hunter_tools.kb_recommend(signals=signals or [], finding=finding, target=target, limit=5)
    workspace_rec = _workspace.recommend(case_slug=case_slug, signals=signals or [], finding=finding, target=target, limit=5)
    return _json_dumps({
        "target": target,
        "signals": signals or [],
        "finding": finding,
        "recommendations": recommendations,
        "proof_goals": [item["proof_goal"] for item in recommendations[:5]],
        "hunter_tools": hunter_tools_rec.get("data", {}),
        "workspace": workspace_rec.get("data", {}),
        "routing_rule": "逻辑漏洞/认证边界优先；每个结论必须有可重复请求、响应差异和影响数据。",
    })



# ============================================================
# OpenTgtyLab Workspace Tools
# ============================================================

@mcp.tool()
async def hunter_workspace_health() -> str:
    """Check OpenTgtyLab root, cases, KB boards, and artifact routes."""
    return _json_dumps(_workspace.health())

@mcp.tool()
async def hunter_case_open(case_slug: str) -> str:
    """Read cases/<slug>/state.json from the OpenTgtyLab workspace."""
    return _json_dumps(_workspace.case_open(case_slug))

@mcp.tool()
async def hunter_case_status(case_slug: str) -> str:
    """Read compact status for an OpenTgtyLab case."""
    return _json_dumps(_workspace.case_status(case_slug))

@mcp.tool()
async def hunter_case_update(case_slug: str, updates: Dict[str, Any]) -> str:
    """Atomically merge controlled fields into a case state.json."""
    return _json_dumps(_workspace.case_update(case_slug, updates))

@mcp.tool()
async def hunter_case_next_steps(case_slug: str) -> str:
    """Read next_steps from an OpenTgtyLab case."""
    return _json_dumps(_workspace.case_next_steps(case_slug))

@mcp.tool()
async def hunter_project_kb_search(query: str, board: str = "general", limit: int = 20) -> str:
    """Search an OpenTgtyLab knowledge-base board."""
    return _json_dumps(_workspace.kb_search(query, board=board, limit=limit))

@mcp.tool()
async def hunter_project_kb_read(technique_path: str, board: str = "general", max_chars: int = 12000) -> str:
    """Read an exact Markdown technique within an OpenTgtyLab KB board."""
    return _json_dumps(_workspace.kb_read(technique_path, board=board, max_chars=max_chars))

@mcp.tool()
async def hunter_evidence_save(case_slug: str, relative_path: str, content: str, append: bool = False) -> str:
    """Save evidence under exports/evidence/<case>/ with traversal protection."""
    return _json_dumps(_workspace.evidence_save(case_slug, relative_path, content, append=append))

@mcp.tool()
async def hunter_note_write(relative_path: str, content: str, append: bool = False) -> str:
    """Write a note under exports/notes with traversal protection."""
    return _json_dumps(_workspace.note_write(relative_path, content, append=append))

@mcp.tool()
async def hunter_report_publish(relative_path: str, content: str, append: bool = False) -> str:
    """Publish a report under exports/reports with traversal protection."""
    return _json_dumps(_workspace.report_publish(relative_path, content, append=append))

@mcp.tool()
async def hunter_workspace_recommend(case_slug: str = "", signals: Optional[List[str]] = None, finding: str = "", target: str = "", limit: int = 8) -> str:
    """Combine case state, project KB, protocol rules, and Hunter tool routing."""
    return _json_dumps(_workspace.recommend(case_slug=case_slug, signals=signals or [], finding=finding, target=target, limit=limit))


# ============================================================
# Hunter Tools v8.1: KB + Burp Bridge Tools
# ============================================================

@mcp.tool()
async def hunter_kb_list() -> str:
    """List Hunter technique markdown files and payload YAML inventory."""
    return _json_dumps(_hunter_tools.kb_list())


@mcp.tool()
async def hunter_kb_search(query: str, limit: int = 20) -> str:
    """Search Hunter KB by signal/query."""
    return _json_dumps(_hunter_tools.kb_search(query, limit=limit))


@mcp.tool()
async def hunter_kb_read(technique_path: str, max_chars: int = 12000) -> str:
    """Read exact Hunter KB file under payloads/."""
    return _json_dumps(_hunter_tools.kb_read(technique_path, max_chars=max_chars))


@mcp.tool()
async def hunter_kb_recommend(signals: Optional[List[str]] = None, finding: str = "", target: str = "", limit: int = 8) -> str:
    """Recommend Hunter KB files, payloads, tools and Burp proof actions."""
    return _json_dumps(_hunter_tools.kb_recommend(signals=signals or [], finding=finding, target=target, limit=limit))


@mcp.tool()
async def hunter_burp_bridge(action: str, url: str = "", method: str = "GET", headers: Optional[Dict[str, str]] = None,
                             body: str = "", http2: bool = True, regex: str = "", count: int = 50,
                             offset: int = 0, severity_filter: str = "", tab_name: str = "") -> str:
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
    return _json_dumps(_hunter_tools.burp_bridge(action, **kwargs))


@mcp.tool()
async def hunter_burp_repeater(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                               body: str = "", tab_name: str = "", http2: bool = True) -> str:
    """Build a Burp Repeater action descriptor."""
    return _json_dumps(_hunter_tools.burp_repeater(url, method=method, headers=headers or {}, body=body, tab_name=tab_name, http2=http2))


@mcp.tool()
async def hunter_burp_proxy_search(regex: str, count: int = 50, offset: int = 0) -> str:
    """Build a Burp proxy history regex-search action descriptor."""
    return _json_dumps(_hunter_tools.burp_proxy_search(regex, count=count, offset=offset))


@mcp.tool()
async def hunter_burp_scanner_issues(count: int = 50, offset: int = 0, severity_filter: str = "") -> str:
    """Build a Burp scanner issues retrieval action descriptor."""
    return _json_dumps(_hunter_tools.burp_scanner_issues(count=count, offset=offset, severity_filter=severity_filter))


@mcp.tool()
async def hunter_burp_collaborator_workflow(workflow: str, url: str, param: str = "", method: str = "GET", template: str = "") -> str:
    """Build blind SSRF/XXE/CMDI Burp Collaborator workflow plan."""
    return _json_dumps(_hunter_tools.burp_collaborator_workflow(workflow=workflow, url=url, param=param, method=method, template=template))


# ============================================================
# Payload Tools
# ============================================================

@mcp.tool()
async def hunter_burp_import(source_dir: str, target: str, vuln_slug: str, destination_dir: Optional[str] = None) -> str:
    """
    Import Burp-exported request/response/screenshots/evidence into Hunter evidence storage.

    Args:
        source_dir: Directory containing Burp exports
        target: Target URL or host
        vuln_slug: Short vuln label like idor/xss/ssrf
        destination_dir: Optional override for Hunter evidence directory

    Returns:
        JSON with copied evidence file paths and suggested prefix.
    """
    dest = destination_dir or str(HUNTER_DIR / "evidence" / "tool_output")
    result = await asyncio.to_thread(import_burp_evidence, source_dir, target, vuln_slug, dest)
    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
async def hunter_payload_list() -> str:
    """
    List all available payload types in the knowledge base.

    Returns:
        JSON array of payload type names.
    """
    types = _payload_loader.list_types()
    return json.dumps({"payload_types": types, "total": len(types)}, indent=2)


@mcp.tool()
async def hunter_payload_search(keyword: str) -> str:
    """
    Search payload knowledge base by keyword.

    Args:
        keyword: Search term (e.g. "union", "alert(", "OR 1=1")

    Returns:
        JSON with matching payloads and their types.
    """
    results = _payload_loader.search(keyword)
    return json.dumps({
        "keyword": keyword,
        "matches": len(results),
        "results": results[:50],  # Limit to 50 results
    }, indent=2, ensure_ascii=False)


@mcp.tool()
async def hunter_payload_get(payload_type: str, section: Optional[str] = None) -> str:
    """
    Get payloads by type and optional section.

    Args:
        payload_type: Payload type (e.g. "sqli", "xss", "ssrf", "ssti", "lfi", "rce", "jwt", "xxe", "deser", "idor", "info_leak")
        section: Optional section within the type (e.g. "union_based", "blind", "error_based")

    Returns:
        JSON with payloads.
    """
    try:
        if section:
            data = _payload_loader.get_section(payload_type, section)
        else:
            data = _payload_loader.get_payloads(payload_type)

        flat_count = len(_payload_loader.get_all_payloads_flat(payload_type))

        return json.dumps({
            "type": payload_type,
            "section": section,
            "total_payloads": flat_count,
            "data": data,
        }, indent=2, ensure_ascii=False)
    except FileNotFoundError:
        return json.dumps({"error": f"Payload type '{payload_type}' not found"})
    except KeyError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_payload_generate(
    payload_type: str,
    section: str,
    **kwargs,
) -> str:
    """
    Generate payloads with placeholder substitution.

    Args:
        payload_type: Payload type (e.g. "sqli")
        section: Section (e.g. "union_based")
        **kwargs: Placeholder values (e.g. columns=4, table="users")

    Returns:
        JSON with generated payloads.
    """
    try:
        payloads = _payload_loader.generate_payloads(payload_type, section, **kwargs)
        return json.dumps({
            "type": payload_type,
            "section": section,
            "generated": len(payloads),
            "payloads": payloads,
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================
# Session Tools
# ============================================================

@mcp.tool()
async def hunter_session_list() -> str:
    """
    List all scan sessions in this MCP server instance.

    Returns:
        JSON with session list and status.
    """
    sessions = []
    for sid, session in _sessions.items():
        sessions.append({
            "session_id": sid,
            "target": session.target,
            "start_time": session.start_time.isoformat(),
            "entries": len(session.entries),
        })

    return json.dumps({
        "total_sessions": len(sessions),
        "sessions": sessions,
    }, indent=2)


@mcp.tool()
async def hunter_session_status(session_id: str) -> str:
    """
    Get detailed status of a scan session.

    Args:
        session_id: Session ID from hunter_scan

    Returns:
        JSON with session details and audit log.
    """
    session = _sessions.get(session_id)
    if not session:
        return json.dumps({"error": f"Session '{session_id}' not found"})

    return json.dumps({
        "session_id": session_id,
        "target": session.target,
        "start_time": session.start_time.isoformat(),
        "total_entries": len(session.entries),
        "audit_log": json.loads(session.export_json()),
    }, indent=2, ensure_ascii=False)


# ============================================================
# Meta Tools
# ============================================================

@mcp.tool()
async def hunter_agents_list(phase: Optional[str] = None) -> str:
    """
    List all available Hunter agents.

    Args:
        phase: Filter by phase name (e.g. "pre-recon", "recon", "vulnerability-analysis", "exploitation", "reporting").
               If None, returns all agents.

    Returns:
        JSON with agent definitions.
    """
    agents = []

    if phase:
        try:
            pn = PhaseName(phase)
            config = PHASES[pn]
            agent_names = config.agents
        except (ValueError, KeyError):
            return json.dumps({"error": f"Unknown phase: {phase}"})
    else:
        agent_names = list(AGENTS.keys())

    for name in agent_names:
        agent_def = AGENTS.get(name)
        if agent_def:
            agents.append({
                "name": agent_def.name,
                "display_name": agent_def.display_name,
                "description": agent_def.description,
                "model_tier": agent_def.model_tier.value,
                "tools_required": agent_def.tools_required,
                "payload_types": agent_def.payload_types,
                "timeout": agent_def.timeout,
            })

    return json.dumps({
        "total": len(agents),
        "phase_filter": phase,
        "agents": agents,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
async def hunter_phases_list() -> str:
    """
    List all pipeline phases and their agents.

    Returns:
        JSON with phase definitions.
    """
    phases = []
    for pn, config in PHASES.items():
        phases.append({
            "name": pn.value,
            "display_name": config.display_name,
            "agents": config.agents,
            "agent_count": len(config.agents),
            "prerequisites": [p.value for p in config.prerequisites],
            "parallel": config.parallel,
            "max_agents": config.max_agents,
        })

    return json.dumps({"phases": phases}, indent=2, ensure_ascii=False)


@mcp.tool()
async def hunter_report(session_id: str, format: str = "markdown", style: str = "cn-src") -> str:
    """
    Generate report for a completed scan session.

    Args:
        session_id: Session ID from hunter_scan
        format: Output format - "markdown" or "json"

    Returns:
        Formatted report.
    """
    session = _sessions.get(session_id)
    if not session:
        return json.dumps({"error": f"Session '{session_id}' not found"})

    if format == "json":
        return json.dumps(session.export_report_json(), indent=2, ensure_ascii=False)
    else:
        return _render_markdown_report(session, style=style)


# ============================================================
# Entry Point
# ============================================================

def main():
    """Run MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
