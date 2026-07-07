"""
Hunter v7 MCP Server

Exposes Hunter pentest framework as MCP tools for Claude Code.
Claude is the brain, MCP tools are the hands.

Tools:
- Pipeline: hunter_scan, hunter_recon, hunter_vuln_scan
- Agent: hunter_subdomain, hunter_port_scan, hunter_tech_detect, hunter_dir_enum, hunter_js_analyze
- Payload: hunter_payload_list, hunter_payload_search, hunter_payload_get
- Session: hunter_session_list, hunter_session_status
- Meta: hunter_agents_list, hunter_phases_list, hunter_report
"""

import asyncio
import json
import os
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

# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP(
    "hunter",
    instructions="Hunter v7 AI-driven pentest framework. Claude is the brain, MCP tools are the hands. "
    "Use hunter_scan for full pipeline, hunter_recon for recon, individual agents for specific tasks, "
    "and hunter_payload_* for payload knowledge base access.",
)

# Global state
_sessions: Dict[str, AuditSession] = {}
_payload_loader = PayloadLoader(str(HUNTER_DIR / "payloads"))
_hunter = get_hunter()
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
# Auto-* Direct Tools (New in v8)
# ============================================================

@mcp.tool()
async def hunter_auto_csrf(target: str, cookie: str = "") -> str:
    """
    Automated CSRF vulnerability detection and exploit generation.

    Args:
        target: Target URL to scan
        cookie: Optional session cookie

    Returns:
        JSON with forms analyzed, CSRF weaknesses found, and exploit HTML.
    """
    try:
        from core.auto_csrf import scan
        result = scan(target, cookie)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_graphql(target: str) -> str:
    """
    Automated GraphQL vulnerability scanner.

    Args:
        target: Target base URL

    Returns:
        JSON with endpoint discovery, introspection results, private data access, and security checks.
    """
    try:
        from core.auto_graphql import full_scan
        result = full_scan(target)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_websocket(target: str) -> str:
    """
    Automated WebSocket vulnerability scanner.

    Args:
        target: Target URL (will discover WebSocket endpoints)

    Returns:
        JSON with WebSocket endpoint discovery, origin bypass tests, XSS injection tests, CSWSH tests.
    """
    try:
        from core.auto_websocket import full_scan
        result = full_scan(target)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_ssti(target: str, param: str = "q", method: str = "GET") -> str:
    """
    Automated SSTI vulnerability scanner with engine detection.

    Args:
        target: Target URL with injectable parameter
        param: Parameter name to inject
        method: HTTP method (GET/POST)

    Returns:
        JSON with SSTI detection, engine identification, and RCE payloads.
    """
    try:
        from core.auto_ssti import scan
        result = scan(target, param=param, method=method)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_cmd(target: str, param: str = "cmd", method: str = "GET") -> str:
    """
    Automated Command Injection scanner.

    Args:
        target: Target URL with injectable parameter
        param: Parameter name to inject
        method: HTTP method (GET/POST)

    Returns:
        JSON with command injection detection and payloads.
    """
    try:
        from core.auto_cmd import scan
        result = scan(target, param=param, method=method)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_idor(target: str, endpoint: str = "", cookie: str = "") -> str:
    """
    Automated IDOR vulnerability scanner.

    Args:
        target: Target base URL
        endpoint: API endpoint to test
        cookie: Optional session cookie

    Returns:
        JSON with IDOR detection results.
    """
    try:
        from core.auto_idor import AutoIDOR
        idor = AutoIDOR(base_url=target, endpoint=endpoint)
        result = idor.run_full_scan()
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_race(target: str, cookie: str = "") -> str:
    """
    Automated Race Condition scanner using HTTP/2 single-packet attack.

    Args:
        target: Target URL
        cookie: Optional session cookie

    Returns:
        JSON with rate limit detection, race condition candidates, and attack results.
    """
    try:
        from core.auto_race import full_scan
        result = full_scan(target, cookie)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_cors(target: str, cookie: str = "") -> str:
    """
    Automated CORS misconfiguration scanner.

    Args:
        target: Target URL
        cookie: Optional session cookie

    Returns:
        JSON with origin reflection, null origin, subdomain trust, and exploit HTML.
    """
    try:
        from core.auto_cors import scan
        result = scan(target, cookie)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_auto_jwt(target: str, token: str = "", cookie: str = "") -> str:
    """
    Automated JWT vulnerability scanner.

    Args:
        target: Target URL (endpoint that accepts JWT)
        token: JWT token to test
        cookie: Optional session cookie

    Returns:
        JSON with signature verification, none algorithm, algorithm confusion, weak key tests.
    """
    try:
        from core.auto_jwt import AutoJWT
        jwt = AutoJWT(target, token, cookie)
        result = jwt.scan()
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def hunter_unified_scan(target: str, cookie: str = "", collaborator: str = "",
                               phases: Optional[List[str]] = None) -> str:
    """
    Unified scan engine - runs all 11 phases automatically.

    Phases: recon, sqli, xss, ssti, ssrf, xxe, cmd, idor, csrf, graphql, websocket

    Args:
        target: Target URL
        cookie: Optional session cookie
        collaborator: Optional Burp Collaborator domain for OOB testing
        phases: Optional list of specific phases to run

    Returns:
        JSON with comprehensive scan results across all phases.
    """
    try:
        from core.unified_scanner import UnifiedScanner
        scanner = UnifiedScanner(
            target=target,
            session_cookie=cookie,
            collaborator_domain=collaborator,
        )
        result = scanner.run_full_scan(phases=phases)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


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
