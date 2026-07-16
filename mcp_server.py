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
import base64
import binascii
import functools
import hashlib
import http.client
import ipaddress
import inspect
import json
import os
import re
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urljoin, urlparse, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

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
from core.doctor import (
    CONTRACT_FILENAME,
    HunterDoctor,
    load_integration_contract,
)
from core.tool_catalog import classify_tool_inventory
from core.adaptive_engine import AdaptiveEngine, get_mode_profile
from core.recon_cache import ReconCache
from core.reasoning.attack_reasoning import AttackReasoner
from core.unified_scanner import OrchestratorRunner, UnifiedOrchestrationBridge
from core.workflow import UnifiedOrchestrator, WorkflowKernel, WorkflowPolicy
from core.workflow.locking import WorkflowFileLock
from core.session import AttackChain, AttackSessionStore, PostExploitation
from core.session.auto_form_extractor import prepare_auto_login
from core.browser import (
    BrowserController,
    BrowserSessionStore,
    DynamicHookInjector,
)
from core.js_analysis.api_extractor import extract_api
from core.js_analysis.bundle_unpacker import unpack_bundle
from core.js_analysis.deobfuscator import deobfuscate
from core.js_analysis.signature_extractor import extract_signature
from core.reverse import AndroidPipeline, BinaryPipeline, detect_binary_type
from core.memory import (
    FingerprintDatabase,
    PatternEngine,
    TargetMemory,
    TechniqueMemory,
)
from core.request_broker.benchmark import measure_broker_modes

INTEGRATION_CONTRACT_PATH = HUNTER_DIR / CONTRACT_FILENAME
_EXTENSION_TOOL_SOURCES: Dict[str, set[str]] = {}
_EXTENSION_TOOL_COLLISIONS: List[Dict[str, Any]] = []
_REVERSE_LAB_MODULE_CACHE: Dict[Path, Any] = {}
_REVERSE_LAB_ROOT_ENV_NAMES = (
    "OPEN_TGTYLAB_ROOT",
    "OPEN_TGTYLAB_WORKSPACE",
    "TGTYLAB_ROOT",
)
_REVERSE_LAB_RELATIVE_PATH = Path(
    "tools/skills/mcp/ReverseLabToolsMCP/"
    "reverse_lab_tools_mcp.py"
)

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
_adaptive_cache = ReconCache(HUNTER_DIR / "evidence" / "adaptive_cache")
_adaptive_engine = AdaptiveEngine(_adaptive_cache, HUNTER_DIR / "evidence" / "adaptive_raw")
SCAN_SESSION_DIR = HUNTER_DIR / "sessions" / "scans"
JS_ANALYSIS_EVIDENCE_DIR = HUNTER_DIR / "evidence" / "js_analysis"
JS_REPLAY_DIR = Path(os.getenv("OPEN_TGTYLAB_ROOT", r"D:\Open-tgtylab")) / "exports" / "scripts"
JS_ANALYSIS_MAX_BYTES = 10 * 1024 * 1024
JS_ANALYSIS_MAX_SCRIPTS = 32
JS_ANALYSIS_TIMEOUT_SECONDS = 15
BROWSER_MCP_CALL_TIMEOUT_SECONDS = 30.0
REVERSE_PIPELINE_ROOT = Path(os.getenv("OPEN_TGTYLAB_ROOT", r"D:\Open-tgtylab")) / "exports" / "reverse"

def _reset_workspace_adapter(root: Optional[str | Path] = None) -> OpenTgtyLabWorkspaceAdapter:
    """Re-discover workspace after environment/config changes (also useful for tests)."""
    global _workspace
    _workspace = OpenTgtyLabWorkspaceAdapter(root)
    return _workspace
def _workflow_kernel() -> WorkflowKernel:
    """Bind workflow persistence to the active OpenTgtyLab workspace."""
    return WorkflowKernel(_workspace.root)


def _orchestrator_generation_config(
    *,
    mode: str,
    profile: str,
    modules: List[str],
    objective: str,
    success_conditions: List[str],
    proof_types: List[str],
) -> Dict[str, Any]:
    return {
        "mode": mode,
        "profile": profile,
        "modules": UnifiedOrchestrator._modules(modules),
        "objective": objective,
        "success_conditions": list(success_conditions),
        "proof_types": list(proof_types),
    }


def _state_generation_config(state: Dict[str, Any]) -> Dict[str, Any]:
    generation = state.get("orchestrator", {}).get("generation", {})
    config = generation.get("config")
    if config:
        return dict(config)
    objective = state.get("objective", {})
    return _orchestrator_generation_config(
        mode=state.get("policy", {}).get("mode", "interactive"),
        profile=state.get("orchestrator", {}).get("profile", "standard"),
        modules=state.get("orchestrator", {}).get("modules", ["all"]),
        objective=(
            objective.get("text", "")
            if isinstance(objective, dict)
            else str(objective)
        ),
        success_conditions=(
            objective.get("success_conditions", [])
            if isinstance(objective, dict)
            else []
        ),
        proof_types=(
            objective.get("proof_types", [])
            if isinstance(objective, dict)
            else []
        ),
    )


def _prepare_orchestrator_workflow(
    kernel: WorkflowKernel,
    *,
    base_slug: str,
    target_url: str,
    config: Dict[str, Any],
    mode: str,
    profile: str,
    modules: List[str],
) -> tuple[str, Dict[str, Any], bool]:
    objective = str(
        config.get("objective", "unified authorized pentest workflow")
    )
    success_conditions = list(config.get("success_conditions", []))
    proof_types = list(config.get("proof_types", []))
    requested_config = _orchestrator_generation_config(
        mode=mode,
        profile=profile,
        modules=modules,
        objective=objective,
        success_conditions=success_conditions,
        proof_types=proof_types,
    )
    cases_root = kernel.root / "cases"
    generation_lock = WorkflowFileLock(
        cases_root / f".{base_slug}.generation.lock"
    )
    with generation_lock:
        candidates = []
        if cases_root.is_dir():
            for directory in cases_root.iterdir():
                if not directory.is_dir():
                    continue
                if (
                    directory.name != base_slug
                    and not directory.name.startswith(f"{base_slug}-g")
                ):
                    continue
                try:
                    state = kernel.materialize(directory.name)
                except (FileNotFoundError, ValueError, UnicodeError, json.JSONDecodeError):
                    continue
                generation = state.get("orchestrator", {}).get(
                    "generation", {}
                )
                number = int(
                    generation.get(
                        "number",
                        1 if directory.name == base_slug else 0,
                    )
                )
                candidates.append((number, directory.name, state))
        candidates.sort(key=lambda item: (item[0], item[1]))
        latest = candidates[-1] if candidates else None
        resume_requested = bool(config.get("resume", False))
        fresh_requested = bool(config.get("fresh_run", False))
        create_new = latest is None or fresh_requested
        if latest is not None and not resume_requested and not fresh_requested:
            latest_state = latest[2]
            if (
                latest_state.get("orchestrator", {}).get("status")
                == "completed"
                and _state_generation_config(latest_state)
                != requested_config
            ):
                create_new = True

        if create_new:
            number = (latest[0] + 1) if latest else 1
            slug = (
                base_slug
                if number == 1
                else f"{base_slug}-g{number}-{uuid.uuid4().hex[:8]}"
            )
            kernel.create(
                slug,
                objective,
                inputs=[{"type": "url", "value": target_url}],
                mode=mode,
                success_conditions=success_conditions,
                proof_types=proof_types,
            )
            state = kernel.materialize(slug)
            created = True
        else:
            number, slug, state = latest
            created = False
            if state.get("policy", {}).get("mode") != mode:
                policy = dict(state.get("policy", {}))
                policy["mode"] = mode
                kernel.set_policy(slug, policy)
                state = kernel.materialize(slug)

        generation = {
            "id": f"gen-{uuid.uuid4().hex[:12]}",
            "base_slug": base_slug,
            "number": number,
            "config": requested_config,
            "created_at": state.get("created_at", datetime.now().isoformat()),
        }
        existing_generation = state.get("orchestrator", {}).get(
            "generation", {}
        )
        if (
            created
            or existing_generation.get("config") != requested_config
            or existing_generation.get("number") != number
        ):
            kernel._append(
                slug,
                "orchestrator.generation.started",
                {"generation": generation},
            )
        else:
            generation = existing_generation
        return slug, generation, created



_stealth_client = None
_attack_session_store = None
_attack_http_clients = {}
_post_exploitation = PostExploitation()
_browser_store = None
_browser_mcp_caller = None
_target_memory = None
_technique_memory = None
_pattern_engine = PatternEngine()
_fingerprint_database = FingerprintDatabase()
COMMON_WEB_PORTS = (80, 443, 8080, 8443, 9090, 9000, 3000, 5000, 8888)
FAST_RECON_INFO_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/")
FAST_RECON_BASIC_PATHS = ("/login", "/admin", "/api", "/system", "/actuator")

def _reset_stealth_client(state_dir: Optional[str | Path] = None):
    global _stealth_client
    from core.stealth.stealth_http_client import StealthHTTPClient
    _stealth_client = StealthHTTPClient(state_dir or (HUNTER_DIR / "sessions" / "stealth"))
    return _stealth_client

def _get_stealth_client():
    return _stealth_client or _reset_stealth_client()

def _reset_attack_session_store(state_dir: Optional[str | Path] = None):
    global _attack_session_store, _attack_http_clients
    _attack_session_store = AttackSessionStore(
        state_dir or (HUNTER_DIR / "sessions" / "attack")
    )
    _attack_http_clients = {}
    return _attack_session_store

def _get_attack_session_store():
    return _attack_session_store or _reset_attack_session_store()


def _reset_browser_store(state_dir: Optional[str | Path] = None):
    global _browser_store
    _browser_store = BrowserSessionStore(
        state_dir or (HUNTER_DIR / "sessions" / "browser")
    )
    return _browser_store


def _get_browser_store():
    return _browser_store or _reset_browser_store()


def _set_browser_mcp_caller(call_mcp_tool=None):
    global _browser_mcp_caller
    _browser_mcp_caller = call_mcp_tool
    return _browser_mcp_caller


def _threadsafe_browser_mcp_caller(owner_loop=None):
    caller = _browser_mcp_caller
    if caller is None:
        return None
    loop = owner_loop

    async def invoke(backend_name, tool_name, arguments):
        result = caller(backend_name, tool_name, arguments)
        return await result if inspect.isawaitable(result) else result

    async def proxy(backend_name, tool_name, arguments):
        current_loop = asyncio.get_running_loop()
        timeout = max(
            0.001,
            float(BROWSER_MCP_CALL_TIMEOUT_SECONDS),
        )
        if loop is None or current_loop is loop:
            return await asyncio.wait_for(
                invoke(backend_name, tool_name, arguments),
                timeout=timeout,
            )
        coroutine = invoke(backend_name, tool_name, arguments)
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        except Exception:
            coroutine.close()
            raise
        try:
            return await asyncio.wait_for(
                asyncio.wrap_future(future),
                timeout=timeout,
            )
        except TimeoutError:
            future.cancel()
            raise

    return proxy


def _orchestrator_auto_tool_runner(tool_name, arguments):
    implementations = {
        "hunter_auto_sqli": ("core.auto_sqli", "auto_sqli_impl", "base_url"),
        "hunter_auto_xss": ("core.auto_xss", "auto_xss_impl", "base_url"),
        "hunter_auto_ssrf": ("core.auto_ssrf", "auto_ssrf_impl", "base_url"),
        "hunter_auto_ssti": ("core.auto_ssti", "auto_ssti_impl", "base_url"),
        "hunter_auto_cmd": ("core.auto_cmd", "auto_cmd_impl", "base_url"),
        "hunter_auto_xxe": ("core.auto_xxe", "auto_xxe_impl", "base_url"),
        "hunter_auto_idor": ("core.auto_idor", "auto_idor_impl", "url"),
        "hunter_auto_jwt": ("core.auto_jwt", "auto_jwt_impl", "url"),
        "hunter_auto_csrf": ("core.auto_csrf", "scan", "url"),
        "hunter_auto_cors": ("core.auto_cors", "scan", "url"),
        "hunter_auto_access_control": (
            "core.auto_access_control",
            "scan",
            "url",
        ),
        "hunter_auto_graphql": ("core.auto_graphql", "full_scan", "base_url"),
        "hunter_auto_race": ("core.auto_race", "full_scan", "url"),
        "hunter_auto_websocket": (
            "core.auto_websocket",
            "full_scan",
            "url",
        ),
    }
    implementation = implementations.get(str(tool_name))
    if implementation is None:
        return NotImplemented
    module_name, function_name, target_name = implementation
    module = __import__(module_name, fromlist=[function_name])
    function = getattr(module, function_name)
    call_arguments = dict(arguments or {})
    target = str(
        call_arguments.pop("target", "")
        or call_arguments.pop("target_url", "")
        or call_arguments.pop(target_name, "")
    )
    if not target:
        raise ValueError(f"{tool_name} requires target")
    if tool_name == "hunter_auto_sqli" and call_arguments.get("session_id"):
        call_arguments.setdefault(
            "stealth_session_id",
            call_arguments.pop("session_id"),
        )
    else:
        call_arguments.pop("session_id", None)
    if tool_name == "hunter_auto_xxe" and call_arguments.get("collaborator"):
        call_arguments.setdefault("oob_domain", call_arguments.pop("collaborator"))
    return _call_with_supported_kwargs(function, target, **call_arguments)


def _orchestration_services(call_mcp_tool=None):
    services = {
        "stealth_http_client": _get_stealth_client(),
        "attack_reasoner": AttackReasoner(),
    }
    if call_mcp_tool is not None:
        services["call_mcp_tool"] = call_mcp_tool
    return services


def _orchestrator_runner(call_mcp_tool=None):
    services = _orchestration_services(call_mcp_tool)
    services["auto_tool_runner"] = _orchestrator_auto_tool_runner
    bridge = UnifiedOrchestrationBridge(
        services=services,
        call_mcp_tool=call_mcp_tool,
    )
    return OrchestratorRunner(
        bridge,
        services["stealth_http_client"],
        services["attack_reasoner"],
    )


def _browser_controller() -> BrowserController:
    return BrowserController(
        artifact_dir=_get_browser_store().storage_dir,
        call_mcp_tool=_browser_mcp_caller,
    )


def _reset_memory_store(db_path: Optional[str | Path] = None):
    global _target_memory, _technique_memory
    target = Path(
        db_path
        or os.getenv(
            "HUNTER_TARGET_MEMORY_DB",
            str(Path(os.getenv("OPEN_TGTYLAB_ROOT", r"D:\Open-tgtylab")) / "data" / "targets.db"),
        )
    ).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    _target_memory = TargetMemory(target)
    _technique_memory = TechniqueMemory(target)
    return _target_memory, _technique_memory


def _get_memory_store():
    return (
        _target_memory,
        _technique_memory,
    ) if _target_memory is not None and _technique_memory is not None else _reset_memory_store()

def _get_attack_http_client(session):
    from core.stealth.stealth_http_client import StealthHTTPClient

    if session.session_id not in _attack_http_clients:
        client = StealthHTTPClient(session.directory / "http", persist_secrets=False)
        client.session_create(session.target, resume=True)
        _attack_http_clients[session.session_id] = client
    return _attack_http_clients[session.session_id]

def _sync_attack_http_client(session):
    client = _get_attack_http_client(session)
    runtime = client._runtime(session.target)
    state = runtime["state"]
    state["cookies"] = session.cookie_dict()
    state["csrf_tokens"] = {
        key: value
        for page_tokens in session.csrf_tokens.values()
        for key, value in page_tokens.items()
    }
    transport = runtime["transport"]
    if hasattr(transport, "cookies"):
        try:
            transport.cookies.clear()
            transport.cookies.update(state["cookies"])
        except Exception:
            pass
    client._save(state)
    return client

def _resolve_attack_chain(chain_name: str) -> Path:
    raw = Path(chain_name)
    if raw.is_absolute() or raw.parent != Path("."):
        candidate = raw.resolve()
        allowed_roots = [
            (HUNTER_DIR / "chains").resolve(),
            (_workspace.root / "exports" / "scripts").resolve(),
        ]
        if not any(candidate == root or root in candidate.parents for root in allowed_roots):
            raise ValueError("attack chain path is outside approved chain roots")
    else:
        name = raw.name
        if Path(name).suffix.lower() not in {".yaml", ".yml", ".json"}:
            name = f"{name}.yml"
        candidate = (HUNTER_DIR / "chains" / name).resolve()
    if not candidate.is_file():
        raise FileNotFoundError(f"attack chain not found: {chain_name}")
    return candidate

def _attack_request_executor(session, request):
    client = _sync_attack_http_client(session)
    options = dict(request.get("options") or {})
    options["follow_redirects"] = False
    options["allowed_origins"] = list(session.authorization.get("allowed_origins") or [])
    return client.stealth_request(
        request["method"],
        request["url"],
        headers=request.get("headers"),
        data=request.get("data"),
        options=options,
    )

def _attack_exploit_executor(session, details):
    vuln_type = str(details.get("vuln_type") or details.get("type") or "")
    if not vuln_type:
        return {
            "status": "approval-required",
            "reason": "exploit step requires a confirmed vuln_type",
            "details": details,
        }
    supported = set(_post_exploitation.ACTIONS) | set(_post_exploitation.ALIASES)
    if vuln_type not in supported:
        return {
            "status": "approval-required",
            "vuln_type": vuln_type,
            "action": details.get("action") or "exploit",
            "confirmed": bool(details.get("confirmed", False)),
            "execution": "deferred",
            "reason": "This chain step requires an explicitly authorized domain executor.",
        }
    return _post_exploitation.run(
        session,
        vuln_type,
        details,
        approved=bool(details.get("approved", False)),
    )

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


def _decode_base64_text(value: str) -> Optional[str]:
    token = unquote(str(value or "")).strip()
    if (
        len(token) < 4
        or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", token)
    ):
        return None

    padded = token + ("=" * (-len(token) % 4))
    for altchars in (None, b"-_"):
        try:
            decoded = base64.b64decode(
                padded,
                altchars=altchars,
                validate=True,
            )
            text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

        standard = base64.b64encode(decoded).decode("ascii").rstrip("=")
        urlsafe = (
            base64.urlsafe_b64encode(decoded)
            .decode("ascii")
            .rstrip("=")
        )
        if token.rstrip("=") not in {standard, urlsafe}:
            continue
        if text.strip() and all(char.isprintable() for char in text):
            return text
    return None


def _replace_url_path_value(path: str, encoded: str, decoded: str) -> Optional[str]:
    for candidate in (encoded, quote(encoded, safe="")):
        index = path.find(candidate)
        if index < 0:
            continue
        replacement = decoded
        end = index + len(candidate)
        if index and path[index - 1] == "/" and replacement.startswith("/"):
            replacement = replacement[1:]
        if end < len(path) and path[end] == "/" and replacement.endswith("/"):
            replacement = replacement[:-1]
        return path[:index] + replacement + path[end:]
    return None


def _decode_ffuf_url(url: str, input_values: Optional[List[str]] = None) -> str:
    raw_url = str(url or "")
    if not raw_url:
        return raw_url

    parts = urlsplit(raw_url)
    candidates = [
        str(value)
        for value in (input_values or [])
        if isinstance(value, str) and value
    ]
    for candidate in candidates:
        decoded = _decode_base64_text(candidate)
        if decoded is None:
            continue
        path = _replace_url_path_value(parts.path, candidate, decoded)
        if path is not None:
            return urlunsplit(parts._replace(path=path))

    segments = parts.path.split("/")
    for index, segment in enumerate(segments):
        decoded = _decode_base64_text(segment)
        if decoded is None:
            continue
        replacement = decoded.split("/")
        if replacement and replacement[0] == "":
            replacement = replacement[1:]
        segments[index:index + 1] = replacement
        return urlunsplit(parts._replace(path="/".join(segments)))
    return raw_url


def _normalize_ffuf_record(record: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(record)
    raw_url = str(record.get("url") or "")
    normalized["raw_url"] = raw_url
    input_data = record.get("input")
    input_values: List[str] = []
    if isinstance(input_data, dict):
        fuzz_value = input_data.get("FUZZ")
        if isinstance(fuzz_value, str):
            input_values.append(fuzz_value)
        input_values.extend(
            value
            for key, value in input_data.items()
            if key != "FUZZ" and isinstance(value, str)
        )
    normalized["url"] = _decode_ffuf_url(raw_url, input_values)
    return normalized


def _compact_ffuf_results(records: List[Dict[str, Any]], limit: int = 50) -> Dict[str, Any]:
    allowed = {200, 301, 302, 401, 403}
    grouped: Dict[str, List[Any]] = {}
    seen = set()
    valid = []
    for record in records:
        status = _ffuf_status(record.get("status"))
        if status not in allowed:
            continue
        parsed = urlsplit(str(record.get("url") or ""))
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        key = (status, path)
        if key in seen:
            continue
        seen.add(key)
        valid.append((status, path, record))
    for status, path, record in valid[:max(0, int(limit))]:
        key = str(status)
        if status in {301, 302}:
            redirect = str(record.get("redirectlocation") or record.get("redirect") or "")
            grouped.setdefault(key, []).append({
                "path": path,
                "redirect": urljoin(str(record.get("url") or ""), redirect) if redirect else "",
            })
        else:
            grouped.setdefault(key, []).append(path)
    grouped["found"] = len(valid)
    grouped["scanned"] = len(records)
    return grouped


def _ffuf_status(value: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        text = str(value or "").strip()
        return text or "unknown"


def _summarize_ffuf_results(records: List[Dict[str, Any]]) -> str:
    visible = (
        list(records)
        if len(records) < 20
        else [
            record
            for record in records
            if _ffuf_status(record.get("status")) != 404
        ]
    )
    visible = visible[:200]
    grouped: Dict[Any, List[Dict[str, Any]]] = {}
    for record in visible:
        grouped.setdefault(
            _ffuf_status(record.get("status")),
            [],
        ).append(record)

    def sort_key(status: Any) -> tuple:
        return (0, status) if isinstance(status, int) else (1, str(status))

    lines: List[str] = []
    for status in sorted(grouped, key=sort_key):
        status_records = grouped[status]
        lines.append(f"HTTP {status} ({len(status_records)}个):")
        for record in status_records:
            url = str(record.get("url") or record.get("raw_url") or "")
            redirect = str(
                record.get("redirectlocation")
                or record.get("location")
                or ""
            )
            if redirect:
                lines.append(f"  {url} -> {urljoin(url, redirect)}")
            else:
                lines.append(f"  {url}")
    return "\n".join(lines)


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
        "why_not_reportable": "Automated discovery lead lacks stable reproduction and business-impact proof.",
        "review_notes": "Requires manual validation before SRC submission.",
        "business_impact": "",
        "impact_scope": execution.get("target", ""),
        "lead_reason": "Automated scanner output is retained as a lead pending reproducible proof.",
        "src_score": 10.0 if success else 0.0,
    }

    if agent_name in _LEAD_ONLY_AGENTS:
        return metadata

    if status == "timeout":
        metadata["why_not_reportable"] = execution.get("message", "Scanner timed out without proof.")
        metadata["lead_reason"] = metadata["why_not_reportable"]
        metadata["proof_strength"] = ProofStrength.NONE.value
        metadata["src_score"] = 0.0
        return metadata

    if execution.get("count", 0) or execution.get("findings"):
        metadata["proof_strength"] = ProofStrength.WEAK.value
        metadata["src_score"] = 20.0 if success else 5.0
        metadata["why_not_reportable"] = "Candidate findings require reproducible request, response, and impact evidence."
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
    agent_timeout = kwargs.pop("_agent_timeout", None)
    deadline = time.monotonic() + float(agent_timeout) if agent_timeout is not None else None

    def remaining(default: float) -> float:
        if deadline is None:
            return float(default)
        return max(0.1, min(float(default), deadline - time.monotonic()))

    def has_budget() -> bool:
        return deadline is None or deadline - time.monotonic() > 0.25

    def budget_exhausted(tool: str) -> Dict[str, Any]:
        return {
            "status": "timeout",
            "stdout": "",
            "stderr": f"Agent deadline exhausted before starting {tool}",
            "returncode": -1,
        }

    def timed_call(function, *args, default: float, **call_kwargs):
        if deadline is not None:
            call_kwargs["timeout"] = remaining(default)
        return function(*args, **call_kwargs)

    if agent_name == "subdomain":
        raw = timed_call(_hunter.subfinder_enum, host, default=120)
        subdomains = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload(
            "subfinder",
            raw,
            {
                "target": host,
                "subdomains": subdomains,
                "count": len(subdomains),
            },
            {
                "source": raw.get("source", ""),
                "attempts": raw.get("attempts", []),
                "wordlist": raw.get("wordlist", ""),
                "error": raw.get("error", ""),
                "partial": raw.get("partial", False),
                "timed_out": raw.get("timed_out", False),
                "warning": raw.get("warning", ""),
                "elapsed_seconds": raw.get("elapsed_seconds"),
            },
        )

    if agent_name == "port-scan":
        ports = kwargs.get("ports", "top-1000")
        raw = timed_call(_hunter.naabu_scan, host, ports=ports, default=120)
        entries = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("naabu", raw, {
            "target": host,
            "ports": ports,
            "open_ports": entries,
            "count": len(entries),
        })

    if agent_name == "tech-detect":
        probe_raw = timed_call(_hunter.httpx_probe, url, default=120)
        tech_raw = timed_call(_hunter.whatweb_identify, url, default=30) if has_budget() else budget_exhausted("whatweb")
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
        raw = timed_call(_hunter.ffuf_fuzz, url, wordlist=wordlist, default=240)
        records = _parse_json_lines(raw.get("stdout", ""))
        parsed_records = [_normalize_ffuf_record(record) for record in records]
        compact = _compact_ffuf_results(parsed_records, limit=50)
        return _tool_payload("ffuf", raw, {
            "target": url,
            "wordlist": wordlist,
            **compact,
            "count": len(records),
        })

    if agent_name == "js-analyze":
        js_raw = timed_call(_hunter.js_analyze, url, default=60)
        crawl_raw = timed_call(_hunter.katana_crawl, url, default=150) if has_budget() else budget_exhausted("katana")
        wayback_raw = timed_call(_hunter.gau_urls, host, default=60) if has_budget() else budget_exhausted("gau")
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
        crawl_raw = timed_call(_hunter.katana_crawl, url, default=150)
        wayback_raw = timed_call(_hunter.gau_urls, host, default=60) if has_budget() else budget_exhausted("gau")
        js_raw = timed_call(_hunter.js_analyze, url, default=60) if has_budget() else budget_exhausted("getjs")
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
        probe_raw = timed_call(_hunter.httpx_probe, url, default=120)
        waf_raw = timed_call(_hunter.waf_detect, url, default=30) if has_budget() else budget_exhausted("wafw00f")
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
        raw = timed_call(_hunter.dalfox_xss, url, default=120)
        findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("dalfox", raw, {
            "target": url,
            "findings": findings[:200],
            "count": len(findings),
        })

    if agent_name == "sqli-vuln" or agent_name == "sqli-exploit":
        if "?" in url:
            raw = timed_call(_hunter.sqlmap_test, url, level=2, risk=2, default=240)
            findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
            return _tool_payload("sqlmap", raw, {
                "target": url,
                "findings": findings[:200],
                "count": len(findings),
            })
        raw = timed_call(_hunter.nuclei_scan, url, tags="sqli", default=240)
        findings = _dedupe(_nonempty_lines(raw.get("stdout", "")))
        return _tool_payload("nuclei", raw, {
            "target": url,
            "findings": findings[:200],
            "count": len(findings),
        })

    if agent_name in _NUCLEI_TAGS:
        raw = timed_call(_hunter.nuclei_scan, url, tags=_NUCLEI_TAGS[agent_name], default=240)
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
        if agent_name == "subdomain":
            timeout = 120
        elif agent_name in {"js-analyze", "api-discover", "param-discover", "endpoint-map"}:
            timeout = 150
        else:
            timeout = 90
    try:
        worker_timeout = max(0.1, float(timeout) - min(2.0, float(timeout) * 0.1))
        return await asyncio.wait_for(
            asyncio.to_thread(
                _execute_agent,
                agent_name,
                target,
                _agent_timeout=worker_timeout,
                **kwargs,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        result = {
            "status": "timeout",
            "message": f"Agent '{agent_name}' timed out after {timeout}s.",
            "target": target,
            "timeline": [{
                "event": f"{agent_name}_timeout",
                "timeout_seconds": timeout,
                "continued": True,
            }],
        }
        if agent_name == "port-scan":
            result.update({"open_ports": [], "count": 0})
        return result


async def _stealth_probe_url(client, url: str, timeout: float = 3.0) -> Dict[str, Any]:
    try:
        return await asyncio.to_thread(
            client.stealth_request,
            "GET",
            url,
            options={
                "max_retries": 0,
                "jitter": False,
                "timeout": timeout,
                "max_body_chars": 4096,
                "follow_redirects": False,
            },
        )
    except Exception as exc:
        return {"status": "error", "status_code": 0, "headers": {}, "body": "", "error": str(exc)}


def _target_probe_ports(target: str) -> tuple[int, ...]:
    parsed = urlsplit(_normalize_url(target))
    try:
        explicit_port = parsed.port
    except ValueError:
        explicit_port = None
    if explicit_port is not None:
        return (int(explicit_port),)
    return tuple(int(port) for port in COMMON_WEB_PORTS)


def _port_probe_url(target: str, port: int) -> str:
    parsed = urlsplit(_normalize_url(target))
    try:
        explicit_port = parsed.port
    except ValueError:
        explicit_port = None
    if explicit_port == int(port) and parsed.scheme in {"http", "https"}:
        scheme = parsed.scheme
    else:
        scheme = "https" if int(port) in {443, 8443} else "http"
    host = parsed.hostname or _normalize_host(target)
    return f"{scheme}://{host}:{int(port)}/"


async def _passive_port_scan(target: str, fallback_reason: str = "external-tool-timeout") -> Dict[str, Any]:
    client = _get_stealth_client()
    ports = _target_probe_ports(target)
    urls = [_port_probe_url(target, port) for port in ports]
    responses = await asyncio.gather(*(_stealth_probe_url(client, url) for url in urls))
    probes = []
    open_ports = []
    for port, url, response in zip(ports, urls, responses):
        status_code = int(response.get("status_code", 0) or 0)
        headers = dict(response.get("headers") or {})
        if status_code > 0:
            open_ports.append(int(port))
        probes.append({
            "port": int(port),
            "url": url,
            "status_code": status_code,
            "server": headers.get("Server") or headers.get("server") or "",
            "error": str(response.get("error") or ""),
        })
    return {
        "status": "success",
        "target": _normalize_host(target),
        "scan_type": "passive_scan",
        "method": "http_application_probe",
        "open_ports": open_ports,
        "count": len(open_ports),
        "probes": probes,
        "fallback_reason": fallback_reason,
        "timeline": [{
            "event": "port_scan_timeout",
            "fallback": "passive_scan",
            "continued": True,
            "reason": fallback_reason,
        }],
    }


def _technology_names(fingerprints: Dict[str, Any], observations: Dict[str, Any]) -> List[str]:
    names = []
    for value in fingerprints.values():
        if isinstance(value, dict):
            name = str(value.get("name") or "").strip()
            if name and name not in names:
                names.append(name)
    text = (str(observations.get("body") or "") + " " + " ".join(observations.get("paths") or [])).lower()
    headers = {str(key).lower(): str(value).lower() for key, value in (observations.get("headers") or {}).items()}
    if any(signal in text for signal in ("cas login", "cas/login", "authserver", "lyuapserver")) or "tgc=" in headers.get("set-cookie", ""):
        names.append("CAS") if "CAS" not in names else None
    if "actuator" in text or "whitelabel error page" in text or "spring" in text:
        names.append("Spring Boot") if "Spring Boot" not in names else None
    if "jsessionid" in headers.get("set-cookie", "") and "Java" not in names:
        names.append("Java")
    for value in headers.values():
        if "nginx" in value and "nginx" not in names:
            names.append("nginx")
    return names


async def _fast_recon_impl(target: str) -> Dict[str, Any]:
    started = time.monotonic()
    client = _get_stealth_client()
    base = _normalize_url(target).rstrip("/")
    paths = ["/", "/favicon.ico", *FAST_RECON_INFO_PATHS, *FAST_RECON_BASIC_PATHS]
    responses = []
    for path in paths:
        responses.append(await _stealth_probe_url(client, base + path))
    port_result = await _passive_port_scan(target, "fast-recon")
    by_path = dict(zip(paths, responses))
    favicon_response = by_path["/favicon.ico"]
    favicon_body = str(favicon_response.get("body") or "")
    favicon_status = int(favicon_response.get("status_code", 0) or 0)
    favicon_hash = (
        hashlib.sha256(
            favicon_body.encode("utf-8", errors="replace")
        ).hexdigest()
        if favicon_status == 200 and favicon_body
        else ""
    )
    evidence_statuses = {200, 204, 301, 302, 307, 308, 401, 405}
    root_response = by_path["/"]
    combined_headers: Dict[str, Any] = dict(root_response.get("headers") or {})
    root_body = str(root_response.get("body") or "")
    bodies = [root_body[:4096]] if root_body else []
    observed_paths = []
    for path, response in by_path.items():
        if path == "/":
            continue
        status_code = int(response.get("status_code", 0) or 0)
        if status_code not in evidence_statuses:
            continue
        observed_paths.append(path)
        combined_headers.update(dict(response.get("headers") or {}))
        body = str(response.get("body") or "")
        if body:
            bodies.append(body[:4096])
    observations = {
        "target_url": base,
        "host": _normalize_host(target),
        "headers": combined_headers,
        "body": "\n".join(bodies),
        "paths": observed_paths,
        "favicon_hash": favicon_hash,
    }
    fingerprints = _fingerprint_database.detect(observations)
    information_disclosure = {
        path: {
            "status_code": int(by_path[path].get("status_code", 0) or 0),
            "server": dict(by_path[path].get("headers") or {}).get("Server", ""),
        }
        for path in FAST_RECON_INFO_PATHS
        if int(by_path[path].get("status_code", 0) or 0) in {200, 301, 302, 401, 403}
    }
    basic_paths = {
        path: int(by_path[path].get("status_code", 0) or 0)
        for path in FAST_RECON_BASIC_PATHS
    }
    return {
        "status": "success",
        "target": base,
        "scan_type": "passive_scan",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "open_ports": port_result.get("open_ports", []),
        "port_probes": port_result.get("probes", []),
        "technology_stack": _technology_names(fingerprints, observations),
        "fingerprints": fingerprints,
        "favicon": {"status_code": int(favicon_response.get("status_code", 0) or 0), "hash": favicon_hash, "algorithm": "sha256"},
        "information_disclosure": information_disclosure,
        "basic_paths": basic_paths,
        "timeline": port_result.get("timeline", []),
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
    """Run a budgeted, cache-aware adaptive scan. Modes: fast/standard/deep; quick/aggressive remain aliases."""
    session_id = f"hunter-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    session = AuditSession(session_id, target)
    _sessions[session_id] = session
    session.log_event("adaptive_scan_started", {"mode": mode, "phases": phases or []})
    session.save(SCAN_SESSION_DIR)

    async def adaptive_runner(agent_name: str, scan_target: str, **kwargs) -> Dict[str, Any]:
        execution = await _execute_agent_async(agent_name, scan_target, **kwargs)
        execution.update(_discover_evidence_attachments(agent_name, scan_target))
        execution.update(_build_submission_metadata(agent_name, execution))
        agent_def = AGENTS.get(agent_name)
        execution.setdefault("agent", agent_name)
        if agent_def:
            execution.setdefault("display_name", agent_def.display_name)
        return execution

    try:
        result = await _adaptive_engine.execute(target, mode=mode, phases=phases, runner=adaptive_runner)
    except asyncio.CancelledError:
        session.status = "cancelled"
        session.log_event("adaptive_scan_cancelled", {"mode": mode})
        session.save(SCAN_SESSION_DIR)
        raise
    except ValueError as exc:
        session.status = "error"
        session.log_event("adaptive_scan_error", {"mode": mode, "error": str(exc)})
        session.save(SCAN_SESSION_DIR)
        return _json_dumps({"status": "error", "error": str(exc), "target": target, "mode": mode, "session_id": session_id})
    except Exception as exc:
        session.status = "error"
        session.log_event("adaptive_scan_error", {"mode": mode, "error": str(exc)})
        session.save(SCAN_SESSION_DIR)
        return _json_dumps({"status": "error", "error": str(exc), "target": target, "mode": mode, "session_id": session_id})
    session.status = "completed"
    session.log_event("adaptive_scan_complete", result.get("metrics", {}))
    raw_results = result.get("results", [])
    reportable_findings = [_result_to_report_item(item) for item in raw_results if item.get("reportable")]
    lead_findings = [_result_to_report_item(item) for item in raw_results if not item.get("reportable")]
    summary = dict(result.get("compact", {}).get("summary", {}))
    summary.update(result.get("metrics", {}))
    session.set_report_data(reportable_findings=reportable_findings, lead_findings=lead_findings, summary=summary)
    session.save(SCAN_SESSION_DIR)
    compact = result.get("compact", {})
    output = {
        "session_id": session_id,
        "target": target,
        "mode": result.get("profile"),
        "status": result.get("status"),
        "summary": compact.get("summary", {}),
        "signals": compact.get("signals", []),
        "top_findings": compact.get("top_findings", []),
        "artifact_path": compact.get("artifact_path"),
        "bytes": compact.get("bytes", {}),
        "metrics": result.get("metrics", {}),
        "plan": result.get("plan", {}),
    }
    return _json_dumps(output)


@mcp.tool()
async def hunter_fast_scan(target: str, phases: Optional[List[str]] = None, use_cache: bool = True) -> str:
    """Run the low-cost fast adaptive profile and return a compact evidence envelope."""
    result = await _adaptive_engine.execute(target, mode="fast", phases=phases, runner=_execute_agent_async, use_cache=use_cache, adaptive_routing=True, stop_on_proof=True)
    compact = result.get("compact", {})
    return _json_dumps({"status": result.get("status"), "target": target, "profile": "fast", "summary": compact.get("summary", {}), "signals": compact.get("signals", []), "top_findings": compact.get("top_findings", []), "artifact_path": compact.get("artifact_path"), "bytes": compact.get("bytes", {}), "metrics": result.get("metrics", {}), "plan": result.get("plan", {})})


@mcp.tool()
async def hunter_scan_plan(target: str, mode: str = "fast", phases: Optional[List[str]] = None) -> str:
    """Preview adaptive DAG layers, limits, TTL and selected agents without executing them."""
    try:
        plan = _adaptive_engine.plan(target, mode, phases)
        profile = get_mode_profile(mode)
        return _json_dumps({"tool": "hunter_scan_plan", "status": "ok", "data": {"target": target, "profile": {**plan["profile_data"], "layers": [list(layer) for layer in profile.layers]}, "layers": [list(layer) for layer in plan["layers"]], "agents": plan["agents"]}})
    except ValueError as exc:
        return _json_dumps({"tool": "hunter_scan_plan", "status": "error", "error": str(exc)})


@mcp.tool()
async def hunter_scan_benchmark(agent_delay_ms: int = 50, payload_bytes: int = 10000) -> str:
    """Benchmark simulated serial vs DAG execution, cache reuse, and result compaction."""
    result = await _adaptive_engine.benchmark(max(1, agent_delay_ms) / 1000.0, max(256, payload_bytes))
    return _json_dumps({"tool": "hunter_scan_benchmark", "status": "ok", "data": result})


@mcp.tool()
async def hunter_broker_benchmark(samples: int = 20) -> str:
    """Benchmark direct and Broker SDK paths against a deterministic local fixture."""
    class FixtureResponse:
        status_code = 200
        text = "<title>Hunter fixture</title><main>healthy local response</main>"
        headers = {"Content-Type": "text/html"}
        url = "https://broker-fixture.invalid/"
        history = []
        cookies = {}

    class FixtureTransport:
        def request(self, *_args: Any, **_kwargs: Any) -> FixtureResponse:
            return FixtureResponse()

    with tempfile.TemporaryDirectory(prefix="hunter-broker-benchmark-") as directory:
        result = measure_broker_modes(
            state_root=directory,
            url="https://broker-fixture.invalid/",
            samples=max(2, min(int(samples), 200)),
            direct_transport=FixtureTransport(),
            broker_transport_factory=FixtureTransport,
        )
    return _json_dumps({"tool": "hunter_broker_benchmark", "status": "ok", "data": result})


@mcp.tool()
async def hunter_cache_status() -> str:
    """Inspect target/profile adaptive recon cache entries and size."""
    return _json_dumps({"tool": "hunter_cache_status", "status": "ok", "data": _adaptive_cache.status()})


@mcp.tool()
async def hunter_cache_clear(target: str = "", profile: str = "") -> str:
    """Clear adaptive recon cache globally or for a normalized target/profile."""
    return _json_dumps({"tool": "hunter_cache_clear", "status": "ok", "data": _adaptive_cache.clear(target, profile)})


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
    session.save(SCAN_SESSION_DIR)
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
    succeeded = execution.get("status") not in {"error", "timeout"}
    session.log_agent_end(agent_name, succeeded, duration)
    session.status = "completed" if succeeded else "error"
    session.save(SCAN_SESSION_DIR)

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
    execution = await _execute_agent_async("port-scan", target, ports=ports, timeout=10)
    if execution.get("status") in {"timeout", "error"}:
        return _json_dumps(await _passive_port_scan(target, execution.get("status", "timeout")))
    return _json_dumps(execution)


@mcp.tool()
async def hunter_tech_detect(target: str) -> str:
    """
    Detect target technology stack (framework, language, server, CMS).

    Args:
        target: Target URL or domain

    Returns:
        JSON with detected technologies.
    """
    execution = await _execute_agent_async("tech-detect", target, timeout=10)
    if execution.get("status") in {"timeout", "error"}:
        fallback = await asyncio.wait_for(_fast_recon_impl(target), timeout=30)
        return _json_dumps({
            "status": "success",
            "target": fallback["target"],
            "scan_type": "passive_scan",
            "technology_stack": fallback["technology_stack"],
            "fingerprints": fallback["fingerprints"],
            "open_ports": fallback["open_ports"],
            "timeline": [{"event": "tech_detect_timeout", "fallback": "passive_scan", "continued": True}],
        })
    return _json_dumps(execution)


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
async def hunter_fast_recon(target: str) -> str:
    """30-second passive recon using stealth_request instead of external CLIs."""
    try:
        return _json_dumps(await asyncio.wait_for(_fast_recon_impl(target), timeout=30))
    except asyncio.TimeoutError:
        return _json_dumps({
            "status": "timeout",
            "target": _normalize_url(target),
            "scan_type": "passive_scan",
            "open_ports": [],
            "technology_stack": [],
            "information_disclosure": {},
            "basic_paths": {},
            "timeline": [{"event": "fast_recon_timeout", "continued": True}],
        })


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


class _ScriptSourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: List[str] = []
        self.inline_scripts: List[str] = []
        self._inside_script = False
        self._script_has_source = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "script":
            self._inside_script = True
            source = dict(attrs).get("src")
            self._script_has_source = bool(source)
            if source:
                self.sources.append(source)

    def handle_data(self, data: str) -> None:
        if self._inside_script and not self._script_has_source and data.strip():
            self.inline_scripts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._inside_script = False
            self._script_has_source = False


_JS_ANALYSIS_METADATA_HOSTS = {
    "metadata.google",
    "metadata.google.internal",
    "metadata.goog",
}


def _validate_js_analysis_ip(address: str, allow_private: bool = False) -> str:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if not allow_private and (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
    ):
        raise ValueError(f"JS analysis URL uses blocked address: {ip}")
    return str(ip)


def _validate_js_analysis_url(url: str, allow_private: bool = False, resolve_host: bool = True) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("JS analysis URL must use http or https")
    if not parsed.hostname:
        raise ValueError("JS analysis URL must include a hostname")
    if allow_private and os.getenv("HUNTER_ALLOW_PRIVATE_JS_ANALYSIS", "").strip().lower() not in {"1", "true", "yes"}:
        raise PermissionError("private JS analysis requires HUNTER_ALLOW_PRIVATE_JS_ANALYSIS=1")
    if allow_private:
        return
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in _JS_ANALYSIS_METADATA_HOSTS:
        raise ValueError(f"JS analysis URL uses blocked address: {hostname}")
    addresses: set[str] = set()
    try:
        addresses.add(str(ipaddress.ip_address(hostname)))
    except ValueError:
        if resolve_host:
            try:
                addresses.update(
                    result[4][0]
                    for result in socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
                )
            except socket.gaierror as exc:
                raise ValueError(f"unable to resolve JS analysis host: {hostname}") from exc
    for address in addresses:
        _validate_js_analysis_ip(address, allow_private=allow_private)


def _resolve_js_analysis_endpoint(url: str, allow_private: bool = False) -> tuple[Any, str, int]:
    _validate_js_analysis_url(url, allow_private=allow_private, resolve_host=False)
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = []
    for result in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM):
        address = _validate_js_analysis_ip(result[4][0], allow_private=allow_private)
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"unable to resolve JS analysis host: {parsed.hostname}")
    return parsed, addresses[0], port


class _JSAnalysisRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allow_private: bool = False) -> None:
        super().__init__()
        self.allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_js_analysis_url(newurl, allow_private=self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_js_analysis_url(url: str, allow_private: bool = False, max_bytes: int = JS_ANALYSIS_MAX_BYTES) -> tuple[str, str, str, int]:
    if max_bytes < 1:
        raise ValueError("remote input exceeds cumulative 10MB limit")
    current_url = url
    for _ in range(6):
        parsed, address, port = _resolve_js_analysis_endpoint(current_url, allow_private)
        raw_socket = socket.create_connection((address, port), timeout=JS_ANALYSIS_TIMEOUT_SECONDS)
        if parsed.scheme == "https":
            raw_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=parsed.hostname)
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=JS_ANALYSIS_TIMEOUT_SECONDS)
        connection.sock = raw_socket
        target = parsed.path or "/"
        if parsed.query:
            target += f"?{parsed.query}"
        try:
            connection.request("GET", target, headers={"User-Agent": "Hunter-JS-Analysis/1.0", "Host": parsed.netloc})
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location")
                if not location:
                    raise ValueError("redirect response omitted Location")
                current_url = urljoin(current_url, location)
                _validate_js_analysis_url(current_url, allow_private=allow_private)
                continue
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > max_bytes:
                raise ValueError("remote input exceeds cumulative 10MB limit")
            content = response.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise ValueError("remote input exceeds cumulative 10MB limit")
            content_type = response.headers.get_content_type()
            charset = response.headers.get_content_charset() or "utf-8"
            return content_type, content.decode(charset, errors="replace"), current_url, len(content)
        finally:
            connection.close()
    raise ValueError("JS analysis URL exceeded redirect limit")


def _js_fetch_parts(result) -> tuple[str, str, str, int]:
    if len(result) == 4:
        content_type, content, final_url, byte_count = result
        return content_type, content, final_url, int(byte_count)
    content_type, content, final_url = result
    return content_type, content, final_url, len(content.encode("utf-8"))


def _load_js_analysis_input(value: str, allow_private: bool = False) -> Dict[str, Any]:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        _validate_js_analysis_url(value, allow_private=allow_private, resolve_host=False)
        content_type, content, final_url, total_bytes = _js_fetch_parts(
            _fetch_js_analysis_url(value, allow_private=allow_private)
        )
        if total_bytes > JS_ANALYSIS_MAX_BYTES:
            raise ValueError("remote input exceeds cumulative 10MB limit")
        sources = [{"name": final_url, "code": content}]
        if content_type == "text/html" or "<script" in content.lower():
            parser = _ScriptSourceParser()
            parser.feed(content)
            external_sources = list(dict.fromkeys(parser.sources))
            if len(parser.inline_scripts) + len(external_sources) > JS_ANALYSIS_MAX_SCRIPTS:
                raise ValueError(f"HTML input exceeds {JS_ANALYSIS_MAX_SCRIPTS} script limit")
            sources = [{"name": f"{final_url}#inline-{index}", "code": code} for index, code in enumerate(parser.inline_scripts)]
            for source in external_sources:
                remaining_bytes = JS_ANALYSIS_MAX_BYTES - total_bytes
                _, script_code, resolved_url, script_bytes = _js_fetch_parts(
                    _fetch_js_analysis_url(
                        urljoin(final_url, source),
                        allow_private=allow_private,
                        max_bytes=remaining_bytes,
                    )
                )
                total_bytes += script_bytes
                if total_bytes > JS_ANALYSIS_MAX_BYTES:
                    raise ValueError("remote input exceeds cumulative 10MB limit")
                sources.append({"name": resolved_url, "code": script_code})
        if not sources:
            raise ValueError("HTML input did not contain JavaScript")
        return {"kind": "url", "value": final_url, "sources": sources, "script_count": len(sources)}
    path = Path(value).expanduser()
    if path.is_file():
        if path.stat().st_size > JS_ANALYSIS_MAX_BYTES:
            raise ValueError("local input exceeds 10MB limit")
        code = path.read_text(encoding="utf-8", errors="replace")
        return {"kind": "path", "value": str(path.resolve()), "sources": [{"name": path.name, "code": code}], "script_count": 1}
    if any(marker in value for marker in (";", "function", "=>", "fetch(", "axios", "var ", "const ", "let ")):
        if len(value.encode("utf-8")) > JS_ANALYSIS_MAX_BYTES:
            raise ValueError("inline code exceeds 10MB limit")
        return {"kind": "code", "value": "inline", "sources": [{"name": "inline.js", "code": value}], "script_count": 1}
    raise FileNotFoundError(f"JavaScript input not found: {value}")


def _js_artifact_dir(tool: str, input_value: str) -> Path:
    digest = hashlib.sha256(input_value.encode("utf-8", errors="replace")).hexdigest()[:12]
    destination = JS_ANALYSIS_EVIDENCE_DIR / f"{tool.removeprefix('hunter_js_')}_{digest}_{int(time.time())}"
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _js_envelope(tool: str, data: Dict[str, Any], evidence: Dict[str, Any], next_actions: Optional[List[str]] = None) -> str:
    return _json_dumps({"tool": tool, "status": "ok", "data": data, "evidence": evidence, "next_actions": next_actions or []})


def _jshook_signature_plan() -> Dict[str, Any]:
    return {
        "server": "jshook",
        "mode": "external-mcp-handoff",
        "hooks": ["fetch", "XMLHttpRequest.open", "XMLHttpRequest.send", "XMLHttpRequest.setRequestHeader", "axios", "WebSocket.send"],
        "captures": ["original_parameters", "final_url", "final_headers", "final_body", "added_parameters", "call_stack"],
        "observation_schema": {"added_parameters": {"signature": "<captured-value>"}, "parameters": {}, "call_stack": []},
    }


async def _run_js_tool(tool: str, operation, input_value: str) -> str:
    try:
        return await asyncio.to_thread(operation, input_value)
    except Exception as exc:
        return _json_dumps({"tool": tool, "status": "error", "data": {}, "evidence": {}, "next_actions": [], "error": str(exc)})


def _unpack_js_input(input_value: str, allow_private: bool = False) -> str:
    loaded = _load_js_analysis_input(input_value, allow_private=allow_private)
    destination = _js_artifact_dir("hunter_js_unpack", loaded["value"])
    results = [unpack_bundle(source["code"], destination / f"source_{index}", source_name=source["name"]) for index, source in enumerate(loaded["sources"])]
    primary = results[0]
    data = {"bundler": primary["bundler"], "modules": primary.get("modules", []), "sources": len(results)}
    return _js_envelope("hunter_js_unpack", data, {"input": {key: loaded[key] for key in ("kind", "value", "script_count")}, "artifact_dir": str(destination), "results": results})


def _deobfuscate_js_input(input_value: str, allow_private: bool = False) -> str:
    loaded = _load_js_analysis_input(input_value, allow_private=allow_private)
    destination = _js_artifact_dir("hunter_js_deobfuscate", loaded["value"])
    results = []
    for index, source in enumerate(loaded["sources"]):
        result = deobfuscate(source["code"])
        output = destination / f"deobfuscated_{index}.js"
        output.write_text(result["code"], encoding="utf-8")
        results.append({"source": source["name"], "path": str(output), "transformations": result.get("transformations", {})})
    preview = (destination / "deobfuscated_0.js").read_text(encoding="utf-8")[:4000]
    return _js_envelope("hunter_js_deobfuscate", {"code_preview": preview, "sources": results}, {"input": {key: loaded[key] for key in ("kind", "value", "script_count")}, "artifact_dir": str(destination)})


def _extract_api_js_input(input_value: str, allow_private: bool = False) -> str:
    loaded = _load_js_analysis_input(input_value, allow_private=allow_private)
    destination = _js_artifact_dir("hunter_js_extract_api", loaded["value"])
    combined = {"endpoints": [], "websockets": [], "routes": [], "authentication": [], "confirmed": [], "inferred": [], "unresolved": []}
    for source in loaded["sources"]:
        result = extract_api(source["code"], source_name=source["name"])
        for key in combined:
            combined[key].extend(result.get(key, []))
    output = destination / "api_inventory.json"
    output.write_text(_json_dumps(combined), encoding="utf-8")
    return _js_envelope("hunter_js_extract_api", combined, {"input": {key: loaded[key] for key in ("kind", "value", "script_count")}, "artifact": str(output)})


def _extract_signature_js_input(input_value: str, parameter_name: Optional[str], observations: Optional[List[Dict[str, Any]]] = None, allow_private: bool = False) -> str:
    loaded = _load_js_analysis_input(input_value, allow_private=allow_private)
    source = "\n".join(item["code"] for item in loaded["sources"])
    result = extract_signature(source, parameter_name=parameter_name, observations=observations, target_url=loaded["value"] if loaded["kind"] == "url" else "", output_dir=JS_REPLAY_DIR)
    destination = _js_artifact_dir("hunter_js_extract_signature", loaded["value"])
    output = destination / "signature_analysis.json"
    output.write_text(_json_dumps({key: value for key, value in result.items() if key != "replay_code"}), encoding="utf-8")
    evidence = {"input": {key: loaded[key] for key in ("kind", "value", "script_count")}, "artifact": str(output), "replay_script": result.get("replay_script")}
    data = {key: value for key, value in result.items() if key not in {"replay_code", "candidates"}}
    data["analysis_mode"] = "static+observed" if observations else "static-only"
    data["dynamic_hook_plan"] = _jshook_signature_plan()
    return _js_envelope("hunter_js_extract_signature", data, evidence, ["Validate the generated replay script against an authorized captured request."])


def _full_analysis_js_input(input_value: str, parameter_name: Optional[str], observations: Optional[List[Dict[str, Any]]] = None, allow_private: bool = False) -> str:
    loaded = _load_js_analysis_input(input_value, allow_private=allow_private)
    destination = _js_artifact_dir("hunter_js_full_analysis", loaded["value"])
    unpacked = []
    deobfuscated = []
    api_inventory = {"endpoints": [], "websockets": [], "routes": [], "authentication": [], "confirmed": [], "inferred": [], "unresolved": []}
    transformed_sources = []
    for index, source in enumerate(loaded["sources"]):
        unpacked_result = unpack_bundle(source["code"], destination / f"source_{index}" / "unpacked", source_name=source["name"])
        unpacked.append(unpacked_result)
        deobfuscated_result = deobfuscate(source["code"])
        transformed_sources.append({"name": source["name"], "code": deobfuscated_result["code"]})
        deobfuscated_path = destination / f"source_{index}" / "deobfuscated.js"
        deobfuscated_path.parent.mkdir(parents=True, exist_ok=True)
        deobfuscated_path.write_text(deobfuscated_result["code"], encoding="utf-8")
        deobfuscated.append({"source": source["name"], "path": str(deobfuscated_path), "transformations": deobfuscated_result["transformations"], "rename_map": deobfuscated_result.get("rename_map", {})})
        api_result = extract_api(deobfuscated_result["code"], source_name=source["name"])
        for key in api_inventory:
            api_inventory[key].extend(api_result.get(key, []))
    combined_code = "\n".join(item["code"] for item in transformed_sources)
    signature = extract_signature(
        combined_code,
        parameter_name=parameter_name,
        observations=observations,
        target_url=loaded["value"] if loaded["kind"] == "url" else "",
        output_dir=JS_REPLAY_DIR,
    )
    api_path = destination / "api_inventory.json"
    api_path.write_text(_json_dumps(api_inventory), encoding="utf-8")
    signature_path = destination / "signature_analysis.json"
    signature_path.write_text(_json_dumps({key: value for key, value in signature.items() if key != "replay_code"}), encoding="utf-8")
    data = {
        "pipeline": {
            "input_sources": len(loaded["sources"]),
            "unpacked_sources": len(unpacked),
            "deobfuscated_sources": len(deobfuscated),
            "downstream_input": "deobfuscated",
        },
        "unpack": unpacked,
        "deobfuscation": deobfuscated,
        "api": api_inventory,
        "signature": {key: value for key, value in signature.items() if key not in {"replay_code", "candidates"}},
    }
    evidence = {
        "input": {key: loaded[key] for key in ("kind", "value", "script_count")},
        "artifact_dir": str(destination),
        "api_inventory": str(api_path),
        "signature_analysis": str(signature_path),
        "replay_script": signature.get("replay_script"),
    }
    return _js_envelope("hunter_js_full_analysis", data, evidence, ["Validate inferred endpoints and signature assumptions with JSHook or Burp evidence."])


@mcp.tool()
async def hunter_js_unpack(input_value: str, allow_private: bool = False) -> str:
    """Unpack a JavaScript bundle from inline code, local path, or HTTP(S) URL."""
    return await _run_js_tool("hunter_js_unpack", lambda value: _unpack_js_input(value, allow_private), input_value)


@mcp.tool()
async def hunter_js_deobfuscate(input_value: str, allow_private: bool = False) -> str:
    """Deobfuscate JavaScript from inline code, local path, or HTTP(S) URL."""
    return await _run_js_tool("hunter_js_deobfuscate", lambda value: _deobfuscate_js_input(value, allow_private), input_value)


@mcp.tool()
async def hunter_js_extract_api(input_value: str, allow_private: bool = False) -> str:
    """Extract APIs from JavaScript or scripts referenced by an HTML URL."""
    return await _run_js_tool("hunter_js_extract_api", lambda value: _extract_api_js_input(value, allow_private), input_value)


@mcp.tool()
async def hunter_js_extract_signature(input_value: str, parameter_name: Optional[str] = None, observations: Optional[List[Dict[str, Any]]] = None, allow_private: bool = False) -> str:
    """Locate request-signature logic and generate a Python replay scaffold."""
    return await _run_js_tool("hunter_js_extract_signature", lambda value: _extract_signature_js_input(value, parameter_name, observations, allow_private), input_value)


@mcp.tool()
async def hunter_js_full_analysis(input_value: str, parameter_name: Optional[str] = None, observations: Optional[List[Dict[str, Any]]] = None, allow_private: bool = False) -> str:
    """Run unpack, deobfuscation, API extraction, and signature analysis."""
    return await _run_js_tool("hunter_js_full_analysis", lambda value: _full_analysis_js_input(value, parameter_name, observations, allow_private), input_value)


def _reverse_envelope(
    tool: str,
    data: Dict[str, Any],
    evidence: Optional[Dict[str, Any]] = None,
    next_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "tool": tool,
        "status": "ok",
        "data": data,
        "evidence": evidence or {},
        "next_actions": next_actions or [],
    }


def _reverse_pipeline_class(sample_path: str | Path, sample_type: str = "auto"):
    normalized = str(sample_type or "auto").strip().lower()
    detected = detect_binary_type(sample_path)
    if normalized == "auto":
        normalized = detected
    if normalized == "mach-o":
        normalized = "macho"
    normalized_detected = "macho" if detected == "mach-o" else detected
    if detected != "unknown" and normalized != normalized_detected:
        raise ValueError(
            f"requested type {normalized!r} does not match detected type {normalized_detected!r}"
        )
    if normalized == "apk":
        return AndroidPipeline, normalized
    if normalized not in {"pe", "elf", "macho", "dex", "firmware", "script"}:
        raise ValueError("type must be auto, pe, elf, macho, apk, dex, firmware, or script")
    return BinaryPipeline, normalized


def _load_reverse_pipeline(pipeline_id: str):
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", pipeline_id)
        or ".." in pipeline_id
    ):
        raise ValueError("pipeline_id must be a safe relative identifier")
    root = REVERSE_PIPELINE_ROOT.expanduser().resolve()
    state_path = root / pipeline_id / "state.json"
    if not state_path.is_file():
        state_path = None
        for candidate in root.rglob("state.json"):
            resolved_candidate = candidate.resolve()
            if root not in resolved_candidate.parents:
                continue
            try:
                candidate_state = json.loads(
                    resolved_candidate.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                continue
            if candidate_state.get("pipeline_id") == pipeline_id:
                state_path = resolved_candidate
                break
    if state_path is None or not state_path.is_file():
        raise KeyError(f"reverse pipeline not found: {pipeline_id}")
    resolved_state = state_path.resolve()
    if root not in resolved_state.parents:
        raise ValueError("pipeline state resolves outside reverse pipeline root")
    state = json.loads(resolved_state.read_text(encoding="utf-8"))
    pipeline_class = AndroidPipeline if state.get("pipeline_kind") == "android" else BinaryPipeline
    return pipeline_class.load(pipeline_id, output_root=root)


@mcp.tool()
async def hunter_reverse_binary(sample_path: str, type: str = "auto") -> str:
    """Run the authorized binary/APK reverse-analysis pipeline and persist its state."""
    def operate() -> Dict[str, Any]:
        pipeline_class, normalized_type = _reverse_pipeline_class(sample_path, type)
        pipeline = pipeline_class(
            sample_path,
            output_root=REVERSE_PIPELINE_ROOT,
        )
        state = pipeline.run_all()
        triage = state.get("results", {}).get("triage", {})
        return _reverse_envelope(
            "hunter_reverse_binary",
            {
                "pipeline_id": state["pipeline_id"],
                "pipeline_kind": state.get("pipeline_kind", "binary"),
                "status": state["status"],
                "sample": {
                    "path": state["sample_path"],
                    "type": triage.get("binary_type", normalized_type),
                    "hashes": triage.get("hashes", {}),
                },
                "steps": state["steps"],
                "artifacts": state.get("artifacts", {}),
                "handoffs": state.get("handoffs", []),
                "state_path": state["state_path"],
            },
            {
                "sample_path": str(Path(sample_path).expanduser().resolve()),
                "state_path": state["state_path"],
            },
            state.get("next_actions", []),
        )

    return await _safe_json_tool("hunter_reverse_binary", operate, timeout=1800)


@mcp.tool()
async def hunter_reverse_step(pipeline_id: str, step_name: str) -> str:
    """Execute or refresh one persisted reverse-pipeline step."""
    def operate() -> Dict[str, Any]:
        pipeline = _load_reverse_pipeline(pipeline_id)
        state = pipeline.run_step(step_name)
        return _reverse_envelope(
            "hunter_reverse_step",
            {
                "pipeline_id": pipeline_id,
                "step_name": step_name,
                "status": state["status"],
                "step": next(item for item in state["steps"] if item["name"] == step_name),
                "artifacts": state.get("artifacts", {}),
                "handoffs": state.get("handoffs", []),
            },
            {"state_path": state["state_path"]},
            state.get("next_actions", []),
        )

    return await _safe_json_tool("hunter_reverse_step", operate, timeout=1800)


@mcp.tool()
async def hunter_reverse_extract_iocs(pipeline_id: str) -> str:
    """Extract and persist IOC indicators from a reverse pipeline."""
    def operate() -> Dict[str, Any]:
        pipeline = _load_reverse_pipeline(pipeline_id)
        result = pipeline.extract_iocs()
        return _reverse_envelope(
            "hunter_reverse_extract_iocs",
            {
                "pipeline_id": pipeline_id,
                "iocs": result,
                "artifact": pipeline.state.get("artifacts", {}).get("iocs", ""),
            },
            {"state_path": pipeline.state["state_path"]},
        )

    return await _safe_json_tool("hunter_reverse_extract_iocs", operate)


@mcp.tool()
async def hunter_reverse_generate_rules(pipeline_id: str) -> str:
    """Generate YARA and Sigma detection-rule artifacts for a reverse pipeline."""
    def operate() -> Dict[str, Any]:
        pipeline = _load_reverse_pipeline(pipeline_id)
        result = pipeline.generate_rules()
        return _reverse_envelope(
            "hunter_reverse_generate_rules",
            {"pipeline_id": pipeline_id, **result},
            {"state_path": pipeline.state["state_path"]},
        )

    return await _safe_json_tool("hunter_reverse_generate_rules", operate)


@mcp.tool()
async def hunter_reverse_decrypt_plan(pipeline_id: str) -> str:
    """Generate a decrypt/unpack plan and external backend handoffs."""
    def operate() -> Dict[str, Any]:
        pipeline = _load_reverse_pipeline(pipeline_id)
        result = pipeline.decrypt_plan()
        return _reverse_envelope(
            "hunter_reverse_decrypt_plan",
            {"pipeline_id": pipeline_id, **result},
            {"state_path": pipeline.state["state_path"]},
            result.get("next_actions", []),
        )

    return await _safe_json_tool("hunter_reverse_decrypt_plan", operate)


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


_auto_session_context = threading.local()
_auto_session_dispatchers: Dict[str, Any] = {}
_auto_session_dispatch_lock = threading.Lock()


def _install_auto_session_dispatcher(module):
    """Install a thread-local override around a module's legacy session factory."""
    module_name = module.__name__
    with _auto_session_dispatch_lock:
        if module_name in _auto_session_dispatchers:
            return
        original = getattr(module, "_get_session", None)
        if original is None:
            raise RuntimeError(f"{module_name} does not expose _get_session")

        def dispatch():
            factory = getattr(_auto_session_context, "factory", None)
            return factory() if factory is not None else original()

        module._get_session = dispatch
        _auto_session_dispatchers[module_name] = original


def _call_auto_with_session(module, func, session_id, args, kwargs):
    _install_auto_session_dispatcher(module)
    detection_session = _get_stealth_client().detection_session(session_id)
    previous = getattr(_auto_session_context, "factory", None)
    _auto_session_context.factory = lambda: detection_session
    try:
        return _call_with_supported_kwargs(func, *args, **kwargs)
    finally:
        if previous is None:
            try:
                del _auto_session_context.factory
            except AttributeError:
                pass
        else:
            _auto_session_context.factory = previous


_AUTO_VERDICT_TYPES = {
    "hunter_auto_sqli": "sqli",
    "hunter_auto_xss": "xss",
    "hunter_auto_ssrf": "ssrf",
    "hunter_auto_xxe": "xxe",
    "hunter_auto_csrf": "csrf",
    "hunter_auto_ssti": "ssti",
    "hunter_auto_cmd": "rce",
    "hunter_auto_idor": "idor",
    "hunter_auto_access_control": "auth_bypass",
    "hunter_auto_race": "race",
}


def _assess_auto_result(tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a centralized verdict without trusting legacy booleans."""
    vuln_name = _AUTO_VERDICT_TYPES.get(tool_name)
    if not vuln_name:
        return result

    from core.evidence.verdict_engine import (
        Evidence, Verdict, VerdictEngine, VerdictResult, VulnType,
    )

    raw_evidence = result.get("evidence")
    if isinstance(raw_evidence, Evidence):
        evidence = raw_evidence
    elif isinstance(raw_evidence, dict):
        evidence = Evidence.from_mapping(raw_evidence)
    else:
        evidence = Evidence({}, {}, {}, "", 0, {})

    browser_verification = evidence.metadata.get("browser_verification", {})
    browser_verdict = str(browser_verification.get("verdict", "")).upper()
    browser_available = not browser_verification.get("browser_unavailable", True)
    if vuln_name == "xss" and browser_available and browser_verdict in {
        "VERIFIED", "LIKELY", "INCONCLUSIVE", "REFUTED"
    }:
        selected = Verdict[browser_verdict]
        reasons = {
            "VERIFIED": "Browser observed an alert dialog triggered by the injected payload",
            "LIKELY": "Browser rendered the payload but no alert dialog was observed",
            "INCONCLUSIVE": "Browser rendered the payload but screenshot evidence could not be captured",
            "REFUTED": "Browser loaded the page without rendering or executing the payload",
        }
        signals = ("browser_alert",) if selected is Verdict.VERIFIED else (
            ("browser_rendered_payload",) if selected is Verdict.LIKELY else ()
        )
        verdict = VerdictResult(
            VulnType.XSS,
            selected,
            reasons[browser_verdict],
            signals,
            evidence.reproduction_count,
        )
    else:
        verdict = VerdictEngine().assess(VulnType(vuln_name), evidence)
    if "vulnerable" in result:
        result["legacy_vulnerable"] = bool(result["vulnerable"])
    result["verdict"] = verdict.to_dict()
    result["vulnerable"] = verdict.verdict is Verdict.VERIFIED
    return result

async def _safe_auto_json_tool(
    tool_name: str,
    module,
    func,
    *args,
    session_id: Optional[str] = None,
    timeout: int = 120,
    **kwargs,
) -> str:
    """Run an auto scanner and attach a centralized evidence verdict."""
    def invoke():
        if session_id is None:
            result = _call_with_supported_kwargs(func, *args, **kwargs)
        else:
            result = _call_auto_with_session(
                module,
                func,
                session_id,
                args,
                kwargs,
            )
        if not isinstance(result, dict):
            result = {"result": result}
        return _assess_auto_result(tool_name, result)

    return await _safe_json_tool(tool_name, invoke, timeout=timeout)

def _join_endpoint(target: str, endpoint: str = "") -> str:
    if not endpoint:
        return target
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    return target.rstrip("/") + "/" + endpoint.lstrip("/")


@mcp.tool()
async def hunter_auto_sqli(target: str, param: str = "category", method: str = "GET",
                           session_id: Optional[str] = None, case_slug: str = "",
                           deep_action: str = "") -> str:
    """Lightweight stealth SQL injection detection with optional sqlmap handoff."""
    from core import auto_sqli
    return await _safe_auto_json_tool(
        "hunter_auto_sqli",
        auto_sqli,
        auto_sqli.auto_sqli_impl,
        target,
        param=param,
        method=method,
        stealth_session_id=session_id,
        case_slug=case_slug,
        deep_action=deep_action,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_xss(target: str, param: str = "q", method: str = "GET",
                          session_id: Optional[str] = None,
                          verify_with_browser: bool = False) -> str:
    """Automated XSS scanner."""
    from core import auto_xss

    browser_controller = None
    if verify_with_browser:
        browser_controller = BrowserController(
            artifact_dir=_get_browser_store().storage_dir,
            call_mcp_tool=_threadsafe_browser_mcp_caller(
                asyncio.get_running_loop()
            ),
        )
    return await _safe_auto_json_tool(
        "hunter_auto_xss",
        auto_xss,
        auto_xss.auto_xss_impl,
        target,
        param=param,
        method=method,
        verify_with_browser=verify_with_browser,
        browser_controller=browser_controller,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_ssrf(target: str, param: str = "url", method: str = "GET",
                           collaborator: str = "",
                           session_id: Optional[str] = None) -> str:
    """Automated SSRF scanner."""
    from core import auto_ssrf
    return await _safe_auto_json_tool(
        "hunter_auto_ssrf",
        auto_ssrf,
        auto_ssrf.auto_ssrf_impl,
        target,
        param=param,
        method=method,
        collaborator=collaborator,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_xxe(target: str, param: str = "", method: str = "POST",
                          collaborator: str = "",
                          session_id: Optional[str] = None) -> str:
    """Automated XXE scanner."""
    from core import auto_xxe
    return await _safe_auto_json_tool(
        "hunter_auto_xxe",
        auto_xxe,
        auto_xxe.auto_xxe_impl,
        target,
        param=param,
        method=method,
        oob_domain=collaborator,
        collaborator=collaborator,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_csrf(target: str, cookie: str = "",
                           session_id: Optional[str] = None) -> str:
    """Automated CSRF vulnerability detection and exploit generation."""
    from core import auto_csrf
    return await _safe_auto_json_tool(
        "hunter_auto_csrf",
        auto_csrf,
        auto_csrf.scan,
        target,
        cookie=cookie,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_graphql(target: str,
                              session_id: Optional[str] = None) -> str:
    """Automated GraphQL vulnerability scanner."""
    from core import auto_graphql
    return await _safe_auto_json_tool(
        "hunter_auto_graphql",
        auto_graphql,
        auto_graphql.full_scan,
        target,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_websocket(target: str,
                                session_id: Optional[str] = None) -> str:
    """Automated WebSocket vulnerability scanner."""
    from core import auto_websocket
    return await _safe_auto_json_tool(
        "hunter_auto_websocket",
        auto_websocket,
        auto_websocket.full_scan,
        target,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_ssti(target: str, param: str = "q", method: str = "GET",
                           session_id: Optional[str] = None) -> str:
    """Automated SSTI vulnerability scanner with engine detection."""
    from core import auto_ssti
    return await _safe_auto_json_tool(
        "hunter_auto_ssti",
        auto_ssti,
        auto_ssti.auto_ssti_impl,
        target,
        param=param,
        method=method,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_cmd(target: str, param: str = "cmd", method: str = "GET",
                          session_id: Optional[str] = None) -> str:
    """Automated command injection scanner."""
    from core import auto_cmd
    return await _safe_auto_json_tool(
        "hunter_auto_cmd",
        auto_cmd,
        auto_cmd.auto_cmd_impl,
        target,
        param=param,
        method=method,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_idor(target: str, endpoint: str = "", cookie: str = "",
                           session_id: Optional[str] = None,
                           owner_cookie: str = "", attacker_id: str = "",
                           owner_id: str = "", repetitions: int = 3) -> str:
    """Automated IDOR scanner with optional two-account differential proof."""
    from core import auto_idor
    url = _join_endpoint(target, endpoint)
    return await _safe_auto_json_tool(
        "hunter_auto_idor",
        auto_idor,
        auto_idor.auto_idor_impl,
        url=url,
        cookie=cookie,
        owner_cookie=owner_cookie,
        attacker_id=attacker_id,
        owner_id=owner_id,
        repetitions=repetitions,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_race(target: str, cookie: str = "",
                           session_id: Optional[str] = None,
                           request_spec: str = "", oracle_spec: str = "",
                           reset_spec: str = "", copies: int = 10,
                           rounds: int = 3) -> str:
    """Discover race candidates or execute a control/race/oracle experiment."""
    from core import auto_race
    return await _safe_auto_json_tool(
        "hunter_auto_race",
        auto_race,
        auto_race.full_scan,
        target,
        session_cookie=cookie,
        cookie=cookie,
        request_spec=request_spec,
        oracle_spec=oracle_spec,
        reset_spec=reset_spec,
        copies=copies,
        rounds=rounds,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_cors(target: str, cookie: str = "",
                           session_id: Optional[str] = None) -> str:
    """Automated CORS misconfiguration scanner."""
    from core import auto_cors
    return await _safe_auto_json_tool(
        "hunter_auto_cors",
        auto_cors,
        auto_cors.scan,
        target,
        cookie=cookie,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_jwt(target: str, token: str = "", cookie: str = "",
                          session_id: Optional[str] = None) -> str:
    """Automated JWT vulnerability scanner."""
    from core import auto_jwt

    def _scan():
        jwt = auto_jwt.AutoJWT(target, token, cookie)
        return jwt.scan()

    return await _safe_auto_json_tool(
        "hunter_auto_jwt",
        auto_jwt,
        _scan,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_access_control(target: str, cookie: str = "",
                                     session_id: Optional[str] = None) -> str:
    """Automated access-control scanner."""
    from core import auto_access_control
    return await _safe_auto_json_tool(
        "hunter_auto_access_control",
        auto_access_control,
        auto_access_control.scan,
        target,
        cookie=cookie,
        session_id=session_id,
    )


@mcp.tool()
async def hunter_auto_attack(target: str, options: str = "{}") -> str:
    """Run the complete six-stage Hunter attack pipeline automatically."""
    try:
        config = json.loads(options) if isinstance(options, str) else dict(options or {})
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return _json_dumps({
            "tool": "hunter_auto_attack",
            "status": "error",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "data": {},
            "evidence": {},
            "next_actions": [],
        })
    call_mcp_tool = _threadsafe_browser_mcp_caller(
        asyncio.get_running_loop()
    )
    return await _safe_json_tool(
        "hunter_auto_attack",
        _orchestrator_runner(call_mcp_tool).run,
        target,
        config,
        timeout=240,
    )


@mcp.tool()
async def hunter_unified_scan(target: str, cookie: str = "", collaborator: str = "",
                               phases: Optional[List[str]] = None) -> str:
    """Run the unified scanner through the six-stage orchestration runner."""
    call_mcp_tool = _threadsafe_browser_mcp_caller(
        asyncio.get_running_loop()
    )
    options = {
        "session_cookie": cookie,
        "collaborator": collaborator,
        "requested_phases": list(phases or []),
    }
    return await _safe_json_tool(
        "hunter_unified_scan",
        _orchestrator_runner(call_mcp_tool).run,
        target,
        options,
        timeout=240,
    )


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


def _registered_tool_inventory() -> Dict[str, Any]:
    tool_manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(tool_manager, "_tools", {})
    names = {str(name) for name in tools}
    try:
        contract = load_integration_contract(
            INTEGRATION_CONTRACT_PATH
        )
    except Exception:
        contract = {}
    namespaces = tuple(
        contract.get("optional_extension_namespaces", [])
    )
    core = {name for name in names if name.startswith("hunter_")}
    extensions = {
        source: sorted(names & {str(item) for item in source_names})
        for source, source_names in _EXTENSION_TOOL_SOURCES.items()
    }
    attributed = {
        name
        for source_names in extensions.values()
        for name in source_names
    }
    unattributed_extensions = {
        name
        for name in names - core - attributed
        if namespaces and name.startswith(namespaces)
    }
    if unattributed_extensions:
        extensions["contract_extensions"] = sorted(
            set(extensions.get("contract_extensions", []))
            | unattributed_extensions
        )
    unknown = names - core - attributed - unattributed_extensions
    inventory, invalid_extensions = classify_tool_inventory(
        core,
        extensions,
        unknown,
        namespaces,
        _classifier_extension_collisions(),
    )
    inventory["invalid_extension_tools"] = invalid_extensions
    return inventory


def _registered_hunter_tools() -> List[str]:
    return list(_registered_tool_inventory()["core"])


def _doctor() -> HunterDoctor:
    workspace_root = _workspace.root if _workspace and _workspace.root else None
    inventory = _registered_tool_inventory()
    return HunterDoctor(
        HUNTER_DIR,
        registered_tools=inventory["core"],
        workspace_root=workspace_root,
        extension_tools=inventory["extensions"],
        unknown_tools=inventory["unknown"],
        invalid_extension_tools=inventory.get(
            "invalid_extension_tools",
            [],
        ),
        extension_collisions=inventory["collisions"],
        contract_path=INTEGRATION_CONTRACT_PATH,
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
        "hunter_auto_attack",
        "hunter_auto_sqli", "hunter_auto_xss", "hunter_auto_ssrf", "hunter_auto_ssti",
        "hunter_auto_cmd", "hunter_auto_xxe", "hunter_auto_idor", "hunter_auto_csrf",
        "hunter_auto_cors", "hunter_auto_jwt", "hunter_auto_graphql", "hunter_auto_websocket",
        "hunter_auto_race", "hunter_auto_access_control", "hunter_unified_scan",
        "hunter_healthcheck", "hunter_capabilities", "hunter_recommend_next",
        "hunter_fast_scan", "hunter_fast_recon", "hunter_scan_plan", "hunter_scan_benchmark", "hunter_broker_benchmark", "hunter_cache_status", "hunter_cache_clear",
        "hunter_kb_list", "hunter_kb_search", "hunter_kb_read", "hunter_kb_recommend",
        "hunter_burp_bridge", "hunter_burp_repeater", "hunter_burp_proxy_search",
        "hunter_burp_scanner_issues", "hunter_burp_collaborator_workflow",
        "hunter_js_unpack", "hunter_js_deobfuscate", "hunter_js_extract_api",
        "hunter_js_extract_signature", "hunter_js_full_analysis",
        "hunter_stealth_request", "hunter_stealth_scan", "hunter_session_create",
        "hunter_session_state", "hunter_set_proxy_pool",
        "hunter_session_start", "hunter_session_execute_chain",
        "hunter_session_checkpoint", "hunter_post_exploit",
        "hunter_auto_pentest",
        "hunter_memory_query", "hunter_memory_record",
        "hunter_memory_recommend", "hunter_fingerprint_detect",
        "hunter_memory_stats",
        "hunter_reverse_binary", "hunter_reverse_step",
        "hunter_reverse_extract_iocs", "hunter_reverse_generate_rules",
        "hunter_reverse_decrypt_plan",
    ]
    inventory = _registered_tool_inventory()
    registered_core = inventory["core"]
    tool_counts = inventory["counts"]
    all_registered = sorted(
        registered_core
        + [
            name
            for names in inventory["extensions"].values()
            for name in names
        ]
        + inventory["unknown"]
    )
    missing_mcp = [
        name for name in required_mcp if name not in registered_core
    ]
    external_names = [
        "nuclei", "subfinder", "naabu", "httpx", "ffuf", "katana", "gau",
        "dalfox", "sqlmap", "wafw00f", "whatweb", "getjs",
        "diec", "rizin", "analyzeHeadless", "frida", "apktool", "jadx",
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
            "registered": all_registered,
            "core": registered_core,
            "extensions": inventory["extensions"],
            "unknown": inventory["unknown"],
            "invalid_extension_tools": inventory.get(
                "invalid_extension_tools",
                [],
            ),
            "collisions": inventory["collisions"],
            "collision_count": len(inventory["collisions"]),
            "required": required_mcp,
            "missing": missing_mcp,
            "core_count": tool_counts["core"],
            "extension_count": tool_counts["extensions"],
            "unknown_count": tool_counts["unknown"],
            "total_registered": tool_counts["total"],
            "counts": tool_counts,
        },
        "external_tools": external,
        "wordlists": wordlists,
        "payloads": payloads,
        "hunter_tools": _hunter_tools.health().get("data", {}),
        "workspace": _workspace.health().get("data", {}),
        "integration_v2": _doctor().run()["data"]["checks"],
        "adaptive_engine": {"profiles": ["fast", "standard", "deep"], "cache": _adaptive_cache.status()},
        "notes": [
            "Network scans depend on external CLIs; payload, metadata, and report tools remain available when CLIs are missing.",
            "All auto tools use safe JSON wrappers and do not leak exceptions through MCP.",
        ],
    })


@mcp.tool()
async def hunter_capabilities() -> str:
    """Return the actual Hunter MCP capability matrix for agent-side routing."""
    inventory = _registered_tool_inventory()
    registered = set(inventory["core"])
    tool_counts = inventory["counts"]
    definitions = {
        "hunter_workflow_create": ("workflow", "Create workflow-state-v2 case"),
        "hunter_workflow_open": ("workflow", "Open materialized workflow state"),
        "hunter_workflow_status": ("workflow", "Read compact workflow status"),
        "hunter_workflow_route": ("workflow", "Route target/artifact lanes"),
        "hunter_workflow_plan": ("workflow", "Build bounded backend plan"),
        "hunter_workflow_run": ("workflow", "Run bounded native actions and emit external handoffs"),
        "hunter_workflow_transition": ("workflow", "Validate phase gate and transition"),
        "hunter_workflow_checkpoint": ("workflow", "Persist workflow checkpoint"),
        "hunter_workflow_resume": ("workflow", "Resume workflow state"),
        "hunter_workflow_policy": ("workflow", "Configure interactive/autopilot policy"),
        "hunter_hypothesis_add": ("workflow", "Register testable hypothesis"),
        "hunter_evidence_register": ("workflow", "Register normalized evidence"),
        "hunter_finding_promote": ("workflow", "Promote evidence-backed finding"),
        "hunter_backend_status": ("workflow", "Inspect backend capability contracts"),
        "hunter_lane_catalog": ("workflow", "List CTF workflow lanes"),
        "hunter_recon": ("pipeline", "Recon pipeline"),
        "hunter_vuln_scan": ("pipeline", "Recon + vulnerability-analysis pipeline"),
        "hunter_scan": ("pipeline", "Configurable full pipeline"),
        "hunter_fast_scan": ("adaptive", "Low-cost fast adaptive DAG scan"),
        "hunter_fast_recon": ("recon", "30-second passive stealth reconnaissance"),
        "hunter_scan_plan": ("adaptive", "Preview adaptive DAG and budget"),
        "hunter_scan_benchmark": ("adaptive", "Benchmark parallelism, cache and compaction"),
        "hunter_broker_benchmark": ("broker", "Benchmark local direct and Broker SDK fixture paths"),
        "hunter_cache_status": ("adaptive", "Inspect target/profile recon cache"),
        "hunter_cache_clear": ("adaptive", "Clear adaptive recon cache"),
        "hunter_subdomain": ("recon", "Subdomain enumeration"),
        "hunter_port_scan": ("recon", "Port scanning"),
        "hunter_tech_detect": ("recon", "Technology fingerprinting"),
        "hunter_dir_enum": ("recon", "Directory/path enumeration"),
        "hunter_js_analyze": ("recon", "JavaScript and endpoint extraction"),
        "hunter_js_unpack": ("js-analysis", "Unpack modern JavaScript bundles"),
        "hunter_js_deobfuscate": ("js-analysis", "Conservative JavaScript deobfuscation"),
        "hunter_js_extract_api": ("js-analysis", "Extract HTTP, WebSocket, route, and auth usage"),
        "hunter_js_extract_signature": ("js-analysis", "Locate signature logic and generate replay scripts"),
        "hunter_js_full_analysis": ("js-analysis", "Run the complete JavaScript analysis pipeline"),
        "hunter_reverse_binary": ("reverse-analysis", "Run the persistent binary or Android reverse-analysis pipeline"),
        "hunter_reverse_step": ("reverse-analysis", "Execute one persisted reverse-analysis step"),
        "hunter_reverse_extract_iocs": ("reverse-analysis", "Extract IOC indicators from reverse-analysis evidence"),
        "hunter_reverse_generate_rules": ("reverse-analysis", "Generate YARA and Sigma rule artifacts"),
        "hunter_reverse_decrypt_plan": ("reverse-analysis", "Generate decrypt and unpack execution plans"),
        "hunter_stealth_request": ("stealth-http", "Send adaptive stateful HTTP request"),
        "hunter_stealth_scan": ("stealth-http", "Detect WAF, rate limits, and captcha"),
        "hunter_session_create": ("stealth-http", "Create or restore target HTTP session"),
        "hunter_session_state": ("session", "Inspect attack session by id or stealth session by target"),
        "hunter_set_proxy_pool": ("stealth-http", "Configure classified proxy pool"),
        "hunter_session_start": ("attack-session", "Create a persistent attack session"),
        "hunter_session_execute_chain": ("attack-session", "Execute a bounded YAML/JSON attack chain"),
        "hunter_session_checkpoint": ("attack-session", "Save, restore, or list attack-session checkpoints"),
        "hunter_post_exploit": ("attack-session", "Build an evidence-gated post-exploitation plan"),
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
        "hunter_auto_attack": ("orchestration", "Run adaptive proof-oriented attack orchestration"),
        "hunter_auto_pentest": ("orchestration", "Run the bounded seven-stage unified pentest orchestrator"),
        "hunter_memory_query": ("memory", "Query target history, technique statistics, or patterns"),
        "hunter_memory_record": ("memory", "Record target, attack, finding, or technique observations"),
        "hunter_memory_recommend": ("memory", "Build explainable recommendations from local memory"),
        "hunter_fingerprint_detect": ("memory", "Match passive observations against local fingerprints"),
        "hunter_memory_stats": ("memory", "Inspect target memory and fingerprint statistics"),
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
        "tool_counts": tool_counts,
        "extensions": inventory["extensions"],
        "unknown_tools": inventory["unknown"],
        "invalid_extension_tools": inventory.get(
            "invalid_extension_tools",
            [],
        ),
        "collisions": inventory["collisions"],
        "collision_count": len(inventory["collisions"]),
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

    if any(token in raw for token in ["idor", "user_id", "userid", "uid", "object", "x-id-token", "authorization", "access control", "\u8d8a\u6743", "\u6c34\u5e73\u8d8a\u6743", "\u5782\u76f4\u8d8a\u6743", "\u8bbf\u95ee\u63a7\u5236"]):
        add("hunter_auto_idor", "Object identifiers suggest possible IDOR.", "Use two authorized identities to prove cross-user data access or modification.", 10)
        add("hunter_auto_access_control", "Authorization signals suggest an access-control boundary.", "Compare anonymous, low-privilege, and authorized responses for the same resource.", 9)
    if any(token in raw for token in ["jwt", "token", "idtoken", "secret", "hs256", "hs512", "kid"]):
        add("hunter_auto_jwt", "JWT or token signals warrant signature and claim validation.", "Confirm a bounded token weakness without exposing live secrets.", 8)
    if "cors" in raw or "origin" in raw or "access-control" in raw:
        add("hunter_auto_cors", "CORS or Origin signals warrant cross-origin validation.", "Confirm attacker-origin read access with credentials where applicable.", 7)
    if "graphql" in raw or "introspection" in raw:
        add("hunter_auto_graphql", "GraphQL signals warrant schema and authorization checks.", "Confirm unauthorized introspection or private query access with bounded evidence.", 7)
    if "websocket" in raw or "ws://" in raw or "wss://" in raw:
        add("hunter_auto_websocket", "WebSocket signals warrant handshake and message authorization checks.", "Capture an unauthorized handshake or message action with reproducible traffic.", 6)
    if any(token in raw for token in ["csrf", "form", "state-changing", "referer"]):
        add("hunter_auto_csrf", "State-changing form or Referer signals warrant CSRF validation.", "Produce a bounded proof that a state change succeeds without a valid anti-CSRF control.", 6)
    if any(token in raw for token in ["sqli", "sql", "mysql", "oracle", "postgres", "error near", "union"]):
        add("hunter_auto_sqli", "SQL error or database signals warrant injection validation.", "Confirm a stable error, structured-data, or timing signal without bulk extraction.", 5)
    if any(token in raw for token in ["xss", "script", "dom", "innerhtml", "reflect"]):
        add("hunter_auto_xss", "Reflection or DOM sink signals warrant XSS validation.", "Capture reproducible request, response, and executable browser context evidence.", 5)
    if any(token in raw for token in ["ssrf", "url=", "callback", "metadata", "169.254"]):
        add("hunter_auto_ssrf", "URL, callback, or metadata signals warrant SSRF validation.", "Confirm an authorized collaborator callback or internal-service fingerprint.", 5)
    if any(token in raw for token in ["xml", "xxe", "svg", "doctype"]):
        add("hunter_auto_xxe", "XML, SVG, or DOCTYPE signals warrant XXE validation.", "Confirm file disclosure or an authorized out-of-band interaction.", 5)
    if any(token in raw for token in ["ssti", "template", "jinja", "freemarker", "thymeleaf"]):
        add("hunter_auto_ssti", "Template-engine signals warrant SSTI validation.", "Confirm harmless expression evaluation before higher-impact actions.", 5)
    if any(token in raw for token in ["cmd", "command", "ping", "whoami", "shell"]):
        add("hunter_auto_cmd", "Command-like parameters warrant injection validation.", "Confirm harmless output or an authorized out-of-band marker.", 5)
    if any(token in raw for token in ["race", "coupon", "payment", "balance", "concurrent", "parallel", "race-condition"]):
        add("hunter_auto_race", "Concurrency-sensitive business actions warrant race testing.", "Confirm a reproducible invariant violation with bounded concurrency.", 8)
    if any(token in raw for token in ["swagger", "openapi", "api-docs", "js", "endpoint"]):
        add("hunter_js_analyze", "API documentation or JavaScript signals warrant endpoint discovery.", "Extract endpoints and parameters, then route only evidence-backed checks.", 4)

    if not recommendations:
        add("hunter_recon", "No specific vulnerability signal is available.", "Build an authorized asset and endpoint inventory before targeted checks.", 1)

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
        "routing_rule": "Prioritize logic and authorization boundaries; require reproducible request, response, and impact evidence.",
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
async def hunter_project_kb_search(query: str, board: str = "auto", limit: int = 20) -> str:
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
    SCAN_SESSION_DIR.mkdir(parents=True, exist_ok=True)
    for path in SCAN_SESSION_DIR.glob("*.json"):
        if path.stem not in _sessions:
            try:
                loaded = AuditSession.load(path)
                _sessions[loaded.session_id] = loaded
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
    sessions = []
    for sid, session in _sessions.items():
        sessions.append({
            "session_id": sid,
            "target": session.target,
            "start_time": session.start_time.isoformat(),
            "status": session.status,
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
        path = SCAN_SESSION_DIR / f"{session_id}.json"
        if path.exists():
            try:
                session = AuditSession.load(path)
                _sessions[session_id] = session
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                session = None
    if not session:
        return json.dumps({"error": f"Session '{session_id}' not found"})

    return json.dumps({
        "session_id": session_id,
        "target": session.target,
        "start_time": session.start_time.isoformat(),
        "status": session.status,
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
        path = SCAN_SESSION_DIR / f"{session_id}.json"
        if path.exists():
            try:
                session = AuditSession.load(path)
                _sessions[session_id] = session
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                session = None
    if not session:
        return json.dumps({"error": f"Session '{session_id}' not found"})

    if format == "json":
        return json.dumps(session.export_report_json(), indent=2, ensure_ascii=False)
    else:
        return _render_markdown_report(session, style=style)




# ============================================================
# Stateful adaptive HTTP infrastructure
# ============================================================

@mcp.tool()
async def hunter_session_start(
    target_url: str,
    authorization: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a persistent attack session for an authorized target."""
    try:
        session = _get_attack_session_store().create(
            target_url,
            authorization=authorization or {},
        )
        client = _get_attack_http_client(session)
        stealth_state = client.session_state(target_url)
        fingerprint = client.fingerprints.get(stealth_state["fingerprint_id"])
        session.fingerprint_headers = fingerprint.get("headers", {})
        session.save()
        return _json_dumps(
            {
                "tool": "hunter_session_start",
                "status": "ok",
                "data": session.public_snapshot(),
                "evidence": {"state_path": str(session.state_path)},
                "next_actions": [
                    "Select a bounded chain and review its parameters before execution."
                ],
            }
        )
    except Exception as exc:
        return _json_dumps(
            {
                "tool": "hunter_session_start",
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "data": {},
                "evidence": {},
                "next_actions": [],
            }
        )

@mcp.tool()
async def hunter_session_execute_chain(
    session_id: str,
    chain_name: str,
    params: Optional[Dict[str, Any]] = None,
    auto_extract: bool = True,
) -> str:
    """Execute a bounded attack chain and persist state after every step."""
    def run_chain():
        session = _get_attack_session_store().get(session_id)
        chain = AttackChain.load(
            _resolve_attack_chain(chain_name),
            request_executor=_attack_request_executor,
            exploit_executor=_attack_exploit_executor,
        )
        runtime_params = dict(params or {})
        auto_summary = None
        if auto_extract:
            runtime_params, auto_summary, terminal = prepare_auto_login(
                session,
                chain,
                runtime_params,
                _attack_request_executor,
            )
            if terminal is not None:
                return terminal
        result = chain.execute(session, params=runtime_params)
        if auto_summary is not None:
            result["auto_extract"] = auto_summary
        return result

    try:
        result = await asyncio.to_thread(run_chain)
        domain_status = str(result.get("status") or "ok")
        envelope_status = domain_status if domain_status in {
            "approval-required", "blocked", "failed", "recovery-required", "rejected"
        } else "ok"
        return _json_dumps(
            {
                "tool": "hunter_session_execute_chain",
                "status": envelope_status,
                "data": result,
                "evidence": {
                    "session_id": session_id,
                    "chain": str(_resolve_attack_chain(chain_name)),
                },
                "next_actions": (
                    ["Resolve the blocker or restore its checkpoint."]
                    if result.get("status") == "blocked"
                    else []
                ),
            }
        )
    except Exception as exc:
        return _json_dumps(
            {
                "tool": "hunter_session_execute_chain",
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "data": {},
                "evidence": {},
                "next_actions": [],
            }
        )

@mcp.tool()
async def hunter_session_checkpoint(
    session_id: str,
    action: str,
    name: str = "",
) -> str:
    """Save, restore, or list persistent attack-session checkpoints."""
    def operate():
        session = _get_attack_session_store().get(session_id)
        normalized = action.strip().lower()
        if normalized == "save":
            if not name:
                raise ValueError("checkpoint name is required for save")
            return session.save_checkpoint(name)
        if normalized == "restore":
            if not name:
                raise ValueError("checkpoint name is required for restore")
            result = session.restore_checkpoint(name)
            _sync_attack_http_client(session)
            return result
        if normalized == "list":
            return {"checkpoints": session.checkpoints}
        raise ValueError("action must be save, restore, or list")

    return _workflow_result("hunter_session_checkpoint", operate)

@mcp.tool()
async def hunter_post_exploit(
    session_id: str,
    vuln_type: str,
    vuln_details: Dict[str, Any],
    approved: bool = False,
) -> str:
    """Create an evidence-gated post-exploitation action plan."""
    return _workflow_result(
        "hunter_post_exploit",
        lambda: _post_exploitation.run(
            _get_attack_session_store().get(session_id),
            vuln_type,
            vuln_details,
            approved,
        ),
    )


async def _resolve_browser_operation(value):
    return await value if inspect.isawaitable(value) else value


def _browser_tool_response(
    tool: str,
    data: Dict[str, Any],
    status: str = "ok",
    error: str = "",
) -> str:
    payload = {
        "tool": tool,
        "status": status,
        "data": data,
        "evidence": {},
        "next_actions": [],
    }
    if error:
        payload["error"] = error
    return _json_dumps(payload)


@mcp.tool()
async def hunter_browser_navigate(
    target_url: str,
    wait_for: Optional[Dict[str, Any]] = None,
    execute: bool = False,
) -> str:
    """Create a browser session and optionally execute its Playwright plan."""
    try:
        store = _get_browser_store()
        session = store.create(target_url)
        controller = _browser_controller()
        plan = await _resolve_browser_operation(
            controller.navigate_and_wait(
                target_url,
                wait_for or {},
                execute=execute,
            )
        )
        if execute and controller.execution_adapter is not None:
            status = str(plan.get("status", "error"))
            data = {
                "browser_session_id": session["session_id"],
                "status": status,
                "target_url": target_url,
                "url": str(plan.get("url", target_url)),
                "title": str(plan.get("title", "")),
                "html_length": int(plan.get("html_length", 0) or 0),
                "has_form": bool(plan.get("has_form", False)),
                "has_login": bool(plan.get("has_login", False)),
                "has_websocket": bool(plan.get("has_websocket", False)),
                "plan": plan,
            }
            store.update(
                session["session_id"],
                current_url=data["url"],
                title=data["title"],
                last_plan=plan,
            )
            return _browser_tool_response(
                "hunter_browser_navigate",
                data,
                status=status if status in {"ok", "timeout", "error"} else "error",
                error=str(plan.get("error", "")),
            )
        store.update(session["session_id"], current_url=target_url, last_plan=plan)
        return _browser_tool_response(
            "hunter_browser_navigate",
            {
                "browser_session_id": session["session_id"],
                "target_url": target_url,
                "plan": plan,
            },
        )
    except Exception as exc:
        return _browser_tool_response(
            "hunter_browser_navigate",
            {},
            status="error",
            error=str(exc),
        )


@mcp.tool()
async def hunter_browser_interact(
    browser_session_id: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    execute: bool = False,
) -> str:
    """Build or execute a browser interaction for a stored browser session."""
    try:
        store = _get_browser_store()
        session = store.get(browser_session_id)
        controller = _browser_controller()
        options = dict(params or {})
        normalized = str(action or "").strip().lower().replace("-", "_")
        if normalized == "click":
            plan = controller.click_and_capture(
                options.get("selector") or options.get("target") or options.get("text", ""),
                capture_network=bool(options.get("capture_network", True)),
                execute=execute,
            )
        elif normalized in {"fill", "form", "submit"}:
            plan = controller.fill_form_and_submit(
                options.get("form_fields") or options.get("fields") or {},
                options.get("submit_button") or options.get("submit") or "",
                execute=execute,
            )
        elif normalized in {"scroll", "scroll_load_more"}:
            plan = controller.scroll_and_load_more(
                options.get("scroll_times", 1),
                execute=execute,
            )
        elif normalized in {"login", "auto_login"}:
            plan = controller.auto_login(
                options.get("url") or session["target"],
                options.get("username", ""),
                options.get("password", ""),
                options.get("login_button_selector"),
                execute=execute,
            )
        elif normalized in {"spa", "navigate_spa"}:
            plan = controller.auto_navigate_spa(
                options.get("base_url") or session["target"],
                options.get("target_state", ""),
                execute=execute,
            )
        elif normalized in {"trigger_api", "api"}:
            plan = controller.auto_trigger_api(
                options.get("url") or session["target"],
                options.get("action_description", ""),
                execute=execute,
            )
        elif normalized in {"execute", "evaluate", "execute_in_context"}:
            plan = controller.execute_in_context(options.get("js_code", ""))
            plan["requires_confirmation"] = True
            plan = controller.execute_plan(plan, execute=execute)
        else:
            raise ValueError(
                "action must be click, fill, scroll, login, spa, trigger_api, or execute"
            )
        plan = await _resolve_browser_operation(plan)
        store.update(browser_session_id, last_plan=plan)
        status = (
            str(plan.get("status", "ok"))
            if execute and controller.execution_adapter is not None
            else "ok"
        )
        return _browser_tool_response(
            "hunter_browser_interact",
            {"browser_session_id": browser_session_id, "plan": plan},
            status=status,
            error=str(plan.get("error", "")),
        )
    except Exception as exc:
        return _browser_tool_response(
            "hunter_browser_interact",
            {},
            status="error",
            error=str(exc),
        )


@mcp.tool()
async def hunter_browser_capture_network(
    browser_session_id: str,
    duration: float = 5.0,
    execute: bool = False,
) -> str:
    """Build or execute a plan that collects browser network traffic."""
    try:
        store = _get_browser_store()
        store.get(browser_session_id)
        controller = _browser_controller()
        plan = await _resolve_browser_operation(
            controller.capture_network_traffic(duration, execute=execute)
        )
        store.update(browser_session_id, last_plan=plan)
        status = (
            str(plan.get("status", "ok"))
            if execute and controller.execution_adapter is not None
            else "ok"
        )
        return _browser_tool_response(
            "hunter_browser_capture_network",
            {"browser_session_id": browser_session_id, "plan": plan},
            status=status,
            error=str(plan.get("error", "")),
        )
    except Exception as exc:
        return _browser_tool_response(
            "hunter_browser_capture_network",
            {},
            status="error",
            error=str(exc),
        )


@mcp.tool()
async def hunter_browser_inject_hooks(
    browser_session_id: str,
    hooks: Optional[List[str]] = None,
    strategy: str = "preload",
    refresh_interval_ms: int = 5000,
    execute: bool = False,
) -> str:
    """Build or execute JavaScript observation-hook injection."""
    try:
        store = _get_browser_store()
        session = store.get(browser_session_id)
        controller = _browser_controller()
        injector = DynamicHookInjector()
        selected = hooks or ["xhr", "fetch", "crypto", "storage", "cookie", "websocket"]
        deferred_plan = injector.build_plan(
            selected,
            strategy=strategy,
            refresh_interval_ms=refresh_interval_ms,
        )
        if execute and controller.execution_adapter is not None:
            sources = {hook: injector.read_template(hook) for hook in selected}
            plan = await _resolve_browser_operation(
                controller.inject_hooks(
                    sources,
                    expected_url=session.get("current_url", ""),
                    execute=True,
                )
            )
            plan["requested_strategy"] = deferred_plan["strategy"]
            plan["effective_strategy"] = "postload"
            plan["strategy"] = "postload"
            current_url = str(plan.get("current_url") or session.get("current_url", ""))
            store.update(
                browser_session_id,
                current_url=current_url,
                last_plan=plan,
            )
            status = str(plan.get("status", "error"))
            return _browser_tool_response(
                "hunter_browser_inject_hooks",
                {
                    "browser_session_id": browser_session_id,
                    "status": status,
                    "hook_statuses": plan.get("hook_statuses", []),
                    "requested_strategy": plan["requested_strategy"],
                    "effective_strategy": plan["effective_strategy"],
                    "expected_url": plan.get("expected_url", ""),
                    "current_url": current_url,
                    "plan": plan,
                },
                status=status,
                error=str(plan.get("error", "")),
            )
        plan = deferred_plan
        store.update(browser_session_id, last_plan=plan)
        return _browser_tool_response(
            "hunter_browser_inject_hooks",
            {"browser_session_id": browser_session_id, "plan": plan},
        )
    except Exception as exc:
        return _browser_tool_response(
            "hunter_browser_inject_hooks",
            {},
            status="error",
            error=str(exc),
        )


@mcp.tool()
async def hunter_browser_get_hook_results(
    browser_session_id: str,
    console_messages: Optional[List[str]] = None,
    execute: bool = False,
) -> str:
    """Fetch, ingest, classify, and return redacted browser hook records."""
    try:
        store = _get_browser_store()
        controller = _browser_controller()
        if execute and controller.execution_adapter is not None:
            result = await _resolve_browser_operation(
                controller.get_hook_results(execute=True)
            )
            status = str(result.get("status", "error"))
            if status != "ok":
                return _browser_tool_response(
                    "hunter_browser_get_hook_results",
                    {
                        "browser_session_id": browser_session_id,
                        **result,
                    },
                    status=status,
                    error=str(result.get("error", "")),
                )
            messages = [
                "__HUNTER_HOOK__" + json.dumps(item, ensure_ascii=False)
                for item in result.get("hook_results", [])
            ]
            ingested = store.ingest_console(browser_session_id, messages)
            persisted_messages = [
                "__HUNTER_HOOK__" + json.dumps(item, ensure_ascii=False)
                for item in ingested.get("hook_results", [])
            ]
            classified = controller.classify_hook_messages(persisted_messages)
            data = {
                "browser_session_id": browser_session_id,
                "accepted": ingested["accepted"],
                "rejected": result.get("rejected", 0) + ingested["rejected"],
                "total": ingested["total"],
                "hook_results": ingested["hook_results"],
                "network_requests": classified["network_requests"],
                "crypto_operations": classified["crypto_operations"],
                "storage_operations": classified["storage_operations"],
                "websocket_messages": classified["websocket_messages"],
            }
            return _browser_tool_response(
                "hunter_browser_get_hook_results",
                data,
            )
        if console_messages:
            data = store.ingest_console(browser_session_id, console_messages)
        else:
            session = store.get(browser_session_id)
            data = {
                "browser_session_id": browser_session_id,
                "accepted": 0,
                "rejected": 0,
                "total": len(session.get("hook_results", [])),
                "hook_results": session.get("hook_results", []),
            }
        return _browser_tool_response("hunter_browser_get_hook_results", data)
    except Exception as exc:
        return _browser_tool_response(
            "hunter_browser_get_hook_results",
            {},
            status="error",
            error=str(exc),
        )


@mcp.tool()
async def hunter_browser_snapshot(
    browser_session_id: str,
    include_network: bool = False,
    execute: bool = False,
) -> str:
    """Build or execute a browser snapshot operation."""
    try:
        store = _get_browser_store()
        session = store.get(browser_session_id)
        controller = _browser_controller()
        plan = await _resolve_browser_operation(
            controller.snapshot(
                include_network=include_network,
                execute=execute,
            )
        )
        store.update(browser_session_id, last_plan=plan)
        status = (
            str(plan.get("status", "ok"))
            if execute and controller.execution_adapter is not None
            else "ok"
        )
        return _browser_tool_response(
            "hunter_browser_snapshot",
            {
                "browser_session_id": browser_session_id,
                "current_url": session.get("current_url", ""),
                "plan": plan,
            },
            status=status,
            error=str(plan.get("error", "")),
        )
    except Exception as exc:
        return _browser_tool_response(
            "hunter_browser_snapshot",
            {},
            status="error",
            error=str(exc),
        )


@mcp.tool()
async def hunter_memory_query(
    query_type: str,
    query: str,
) -> str:
    """Query local target history, technique statistics, or reusable patterns."""
    def operate() -> Dict[str, Any]:
        target_memory, technique_memory = _get_memory_store()
        normalized = str(query_type or "").strip().lower()
        if normalized == "target":
            return target_memory.query_target(query)
        if normalized == "technique":
            return {
                "waf": query,
                "techniques": technique_memory.best_for_waf(query),
            }
        if normalized == "pattern":
            return {
                "parameter": _pattern_engine.match_parameter(query),
                "response": _pattern_engine.match_response(query),
            }
        raise ValueError("query_type must be target, technique, or pattern")

    return _workflow_result("hunter_memory_query", operate)


@mcp.tool()
async def hunter_memory_record(
    record_type: str,
    data: Dict[str, Any],
) -> str:
    """Record a bounded target, technique, finding, or attack observation."""
    def operate() -> Dict[str, Any]:
        target_memory, technique_memory = _get_memory_store()
        payload = dict(data or {})
        normalized = str(record_type or "").strip().lower()
        target_url = str(payload.get("target_url") or payload.get("url") or "").strip()
        if normalized == "target":
            result = target_memory.record_target(
                target_url,
                fingerprints=payload.get("fingerprints") or {},
            )
        elif normalized == "fingerprint":
            result = target_memory.record_fingerprint(
                target_url,
                payload.get("fingerprint_type") or payload.get("type") or "",
                payload.get("value") or payload.get("name") or "",
                confidence=payload.get("confidence", 0.0),
                evidence=payload.get("evidence") or {},
            )
        elif normalized == "endpoint":
            result = target_memory.record_endpoint(
                target_url,
                payload.get("path") or payload.get("endpoint") or "",
                method=payload.get("method", "GET"),
                parameters=payload.get("parameters") or [],
                injection_points=payload.get("injection_points") or [],
                authorization_risk=bool(payload.get("authorization_risk", False)),
            )
        elif normalized in {"vulnerability", "vuln"}:
            result = target_memory.record_vulnerability(
                target_url,
                vuln_type=payload.get("vuln_type") or payload.get("type") or "",
                severity=payload.get("severity", "info"),
                status=payload.get("status", "suspected"),
                poc_path=payload.get("poc_path", ""),
                report_path=payload.get("report_path", ""),
            )
        elif normalized == "attack":
            result = target_memory.record_attack(
                target_url,
                tool=payload.get("tool", ""),
                payload_metadata=payload.get("payload_metadata") or {},
                success=bool(payload.get("success", False)),
                bypass_strategy=payload.get("bypass_strategy", ""),
                notes=payload.get("notes", ""),
            )
            if payload.get("technique"):
                technique_memory.record_attempt(
                    target_url=target_url,
                    technique_name=payload["technique"],
                    waf_type=payload.get("waf_type", ""),
                    success=bool(payload.get("success", False)),
                )
        elif normalized in {"technique", "technique_attempt"}:
            if normalized == "technique":
                result = technique_memory.register_technique(
                    payload.get("name") or payload.get("technique_name") or "",
                    payload.get("type") or payload.get("technique_type") or "",
                    payload.get("description", ""),
                )
            else:
                result = technique_memory.record_attempt(
                    target_url=target_url,
                    technique_name=payload.get("technique_name") or payload.get("technique") or "",
                    waf_type=payload.get("waf_type", ""),
                    success=bool(payload.get("success", False)),
                )
        else:
            raise ValueError(
                "record_type must be target, fingerprint, endpoint, vulnerability, "
                "attack, technique, or technique_attempt"
            )
        return {"record_type": normalized, "record": result}

    return _workflow_result("hunter_memory_record", operate)


@mcp.tool()
async def hunter_memory_recommend(
    target_url: str,
) -> str:
    """Return explainable, non-executing recommendations from local memory."""
    def operate() -> Dict[str, Any]:
        target_memory, technique_memory = _get_memory_store()
        history = target_memory.query_target(target_url)
        fingerprints = history.get("fingerprints", {})
        waf = fingerprints.get("waf") or fingerprints.get("waf_type") or ""
        recommendations: List[Dict[str, Any]] = []
        ranked_techniques: List[Dict[str, Any]] = []
        if waf:
            ranked_techniques = technique_memory.best_for_waf(waf)[:5]
            for item in ranked_techniques:
                recommendations.append(
                    {
                        "kind": "technique",
                        "name": item["name"],
                        "reason": f"historical success rate for {waf}: {item['success_rate']:.2f}",
                        "confidence": item["success_rate"],
                    }
                )
            if not ranked_techniques or max(
                (item["success_rate"] for item in ranked_techniques),
                default=0.0,
            ) < 0.10:
                for combination in technique_memory.recommend_combinations(waf)[:3]:
                    recommendations.append(
                        {
                            "kind": "technique-combination",
                            "name": " + ".join(combination["techniques"]),
                            "reason": "single historical techniques have low success; "
                            "combine the highest-ranked independent strategies",
                            "confidence": combination["estimated_success_rate"],
                        }
                    )
        for endpoint in history.get("endpoints", []):
            for parameter in endpoint.get("parameters", []):
                pattern = _pattern_engine.match_parameter(
                    parameter,
                    context=f"{endpoint.get('method', 'GET')} {endpoint.get('url', '')}",
                )
                if pattern.get("vulnerability_types"):
                    recommendations.append(
                        {
                            "kind": "parameter-pattern",
                            "name": str(parameter),
                            "reason": ", ".join(pattern["vulnerability_types"]),
                            "confidence": pattern.get("confidence", 0.0),
                        }
                    )
        stack = _pattern_engine.recommend_stack(fingerprints)
        if stack.get("primary"):
            recommendations.append(
                {
                    "kind": "stack",
                    "name": stack["primary"]["name"],
                    "reason": stack["primary"].get("reason", ""),
                    "confidence": stack.get("confidence", 0.0),
                }
            )
        similar_targets = target_memory.similar_targets(target_url, limit=5)
        for similar in similar_targets:
            similar_history = target_memory.query_target(similar["url"])
            strategies = sorted(
                {
                    attack["bypass_strategy"]
                    for attack in similar_history.get("attack_history", [])
                    if attack.get("success") and attack.get("bypass_strategy")
                }
            )
            for strategy in strategies:
                recommendations.append(
                    {
                        "kind": "similar-target",
                        "name": strategy,
                        "reason": f"worked on similar target {similar['domain']} "
                        f"(similarity {similar['similarity']:.2f})",
                        "confidence": similar["similarity"],
                    }
                )
        return {
            "target_url": target_url,
            "recommendations": recommendations,
            "similar_targets": similar_targets,
            "history_summary": {
                "endpoints": len(history.get("endpoints", [])),
                "vulnerabilities": len(history.get("vulnerabilities", [])),
                "attacks": len(history.get("attack_history", [])),
            },
            "execution": "deferred",
        }

    return _workflow_result("hunter_memory_recommend", operate)


@mcp.tool()
async def hunter_fingerprint_detect(
    target_url: str,
    observations: Optional[Dict[str, Any]] = None,
) -> str:
    """Match passive headers/body/path observations against local fingerprints."""
    def operate() -> Dict[str, Any]:
        passive_observations = dict(observations or {})
        passive_observations.setdefault("target_url", target_url)
        result = _fingerprint_database.detect(passive_observations)
        if observations is None:
            result["plan"] = {
                "mode": "passive-observation-handoff",
                "execution": "deferred",
                "target_url": target_url,
                "required_observations": ["headers", "body", "paths", "favicon_hash"],
            }
        return {"target_url": target_url, **result}

    return _workflow_result("hunter_fingerprint_detect", operate)


@mcp.tool()
async def hunter_memory_stats() -> str:
    """Return local memory database and fingerprint catalog statistics."""
    def operate() -> Dict[str, Any]:
        target_memory, technique_memory = _get_memory_store()
        return {
            "database_path": str(target_memory.db_path),
            "memory": target_memory.stats(),
            "techniques": technique_memory.stats(),
            "fingerprints": _fingerprint_database.counts(),
        }

    return _workflow_result("hunter_memory_stats", operate)


@mcp.tool()
async def hunter_session_create(target: str, resume: bool = True, fingerprint_strategy: str = "random") -> str:
    """Create or restore an isolated target HTTP session."""
    return _workflow_result("hunter_session_create", _get_stealth_client().session_create, target, resume, fingerprint_strategy)

@mcp.tool()
async def hunter_session_state(target: str = "", session_id: str = "") -> str:
    """Inspect an attack session by id, or a stealth HTTP session by target."""
    if target and session_id:
        return _workflow_result(
            "hunter_session_state",
            lambda: (_ for _ in ()).throw(
                ValueError("provide either target or session_id, not both")
            ),
        )
    if session_id:
        return _workflow_result(
            "hunter_session_state",
            lambda: _get_attack_session_store().get(session_id).public_snapshot(),
        )
    if not target:
        return _workflow_result(
            "hunter_session_state",
            lambda: (_ for _ in ()).throw(
                ValueError("target or session_id is required")
            ),
        )
    return _workflow_result(
        "hunter_session_state",
        _get_stealth_client().session_state,
        target,
    )

@mcp.tool()
async def hunter_set_proxy_pool(proxies: Optional[List[str]] = None, file_path: str = "") -> str:
    """Configure the classified HTTP/HTTPS/SOCKS5 proxy pool."""
    return _workflow_result("hunter_set_proxy_pool", _get_stealth_client().set_proxy_pool, proxies or [], file_path or None)

@mcp.tool()
async def hunter_stealth_request(method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None, options: Optional[Dict[str, Any]] = None) -> str:
    """Send a stateful adaptive request with fingerprint, WAF/rate-limit/captcha handling."""
    return _workflow_result("hunter_stealth_request", _get_stealth_client().stealth_request, method, url, headers, data, options or {})

@mcp.tool()
async def hunter_stealth_scan(target: str, options: Optional[Dict[str, Any]] = None) -> str:
    """Run bounded WAF, rate-limit, and captcha reconnaissance for a target."""
    return _workflow_result("hunter_stealth_scan", _get_stealth_client().stealth_scan, target, options or {})

# ============================================================
# Unified CTF / reverse / pentest workflow kernel
# ============================================================

def _workflow_result(tool: str, func, *args, **kwargs) -> str:
    try:
        return _json_dumps({"tool": tool, "status": "ok", "data": func(*args, **kwargs), "evidence": {}, "next_actions": []})
    except Exception as exc:
        return _json_dumps({"tool": tool, "status": "error", "error_type": type(exc).__name__, "error": str(exc), "data": {}, "evidence": {}, "next_actions": []})


async def _async_workflow_result(tool: str, func, *args, **kwargs) -> str:
    try:
        data = await asyncio.to_thread(func, *args, **kwargs)
        return _json_dumps(
            {
                "tool": tool,
                "status": "ok",
                "data": data,
                "evidence": {},
                "next_actions": [],
            }
        )
    except Exception as exc:
        return _json_dumps(
            {
                "tool": tool,
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "data": {},
                "evidence": {},
                "next_actions": [],
            }
        )


@mcp.tool()
async def hunter_workflow_create(case_slug: str, objective: str, inputs: Optional[List[Dict[str, Any]]] = None, mode: str = "interactive", success_conditions: Optional[List[str]] = None, proof_types: Optional[List[str]] = None) -> str:
    return _workflow_result("hunter_workflow_create", _workflow_kernel().create, case_slug, objective, inputs or [], mode, success_conditions or [], proof_types or [])

@mcp.tool()
async def hunter_workflow_open(case_slug: str) -> str:
    return _workflow_result("hunter_workflow_open", _workflow_kernel().open, case_slug)

@mcp.tool()
async def hunter_workflow_status(case_slug: str) -> str:
    return _workflow_result("hunter_workflow_status", _workflow_kernel().status, case_slug)

@mcp.tool()
async def hunter_workflow_route(inputs: Optional[List[Dict[str, Any]]] = None) -> str:
    return _workflow_result("hunter_workflow_route", _workflow_kernel().route, inputs or [])

@mcp.tool()
async def hunter_workflow_plan(case_slug: str, max_actions: int = 5) -> str:
    return _workflow_result("hunter_workflow_plan", _workflow_kernel().plan, case_slug, max_actions)

@mcp.tool()
async def hunter_workflow_run(
    case_slug: str,
    max_actions: int = 5,
    target_url: str = "",
    options: Optional[Dict[str, Any]] = None,
) -> str:
    if target_url or options:
        config = dict(options or {})
        profile = config.get("policy", "standard")
        raw_modules = config.get("modules", ["all"])
        modules = [raw_modules] if isinstance(raw_modules, str) else list(raw_modules)
        mode = config.get("mode", "interactive")
        call_mcp_tool = _threadsafe_browser_mcp_caller(
            asyncio.get_running_loop()
        )
        def orchestrate():
            kernel = _workflow_kernel()
            resolved_target = target_url
            if not resolved_target:
                try:
                    resolved_target = UnifiedOrchestrator._target_from_state(
                        kernel.materialize(case_slug)
                    )
                except FileNotFoundError:
                    resolved_target = ""
            if not resolved_target:
                raise ValueError("target_url is required")
            slug, generation, _ = _prepare_orchestrator_workflow(
                kernel,
                base_slug=case_slug,
                target_url=resolved_target,
                config=config,
                mode=mode,
                profile=profile,
                modules=modules,
            )
            return UnifiedOrchestrator(
                kernel,
                services=_orchestration_services(call_mcp_tool),
            ).orchestrate(
                slug,
                target_url=resolved_target,
                modules=modules,
                policy=profile,
                resume=bool(config.get("resume", False)),
                observations=config.get("observations"),
                approval=config.get("approval"),
                checkpoint_id=config.get("checkpoint_id", ""),
            )
        return await _async_workflow_result(
            "hunter_workflow_run",
            orchestrate,
        )

    def execute_native(action):
        return {"status": "deferred", "summary": "Native MCP dispatch is emitted as a bounded action for the Codex orchestrator.", "action": action}
    return _workflow_result("hunter_workflow_run", _workflow_kernel().run, case_slug, execute_native, max_actions)


@mcp.tool()
async def hunter_auto_pentest(
    target_url: str,
    options: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
) -> str:
    """Run the bounded seven-stage unified orchestrator."""
    config = dict(options or {})
    if session_id is not None:
        try:
            _get_stealth_client().detection_session(session_id)
        except Exception as exc:
            return _json_dumps({
                "tool": "hunter_auto_pentest",
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "data": {},
                "evidence": {},
                "next_actions": [],
            })
        config["session_id"] = session_id
    profile = str(config.get("policy", "standard")).strip().lower()
    raw_modules = config.get("modules", ["all"])
    modules = [raw_modules] if isinstance(raw_modules, str) else list(raw_modules)
    mode = str(config.get("mode", "interactive")).strip().lower()
    if profile not in {"fast", "standard", "deep"}:
        return _json_dumps({
            "tool": "hunter_auto_pentest",
            "status": "error",
            "error_type": "invalid_input",
            "error": "policy must be fast, standard, or deep",
            "data": {},
            "evidence": {},
            "next_actions": [],
        })
    if mode not in {"interactive", "guided", "autopilot"}:
        return _json_dumps({
            "tool": "hunter_auto_pentest",
            "status": "error",
            "error_type": "invalid_input",
            "error": "mode must be interactive, guided, or autopilot",
            "data": {},
            "evidence": {},
            "next_actions": [],
        })
    base_slug = f"auto-pentest-{hashlib.sha256(target_url.encode('utf-8')).hexdigest()[:16]}"
    call_mcp_tool = _threadsafe_browser_mcp_caller(
        asyncio.get_running_loop()
    )

    def orchestrate():
        kernel = _workflow_kernel()
        slug, generation, _ = _prepare_orchestrator_workflow(
            kernel,
            base_slug=base_slug,
            target_url=target_url,
            config=config,
            mode=mode,
            profile=profile,
            modules=modules,
        )
        use_runner = bool(config.get("use_runner", False))
        if use_runner:
            result = _orchestrator_runner(call_mcp_tool).run(
                target_url,
                {
                    **config,
                    "policy": profile,
                    "mode": mode,
                    "modules": modules,
                },
            )
            result.setdefault(
                "execution",
                "deferred" if result.get("handoffs") else "completed",
            )
        else:
            result = UnifiedOrchestrator(
                kernel,
                services=_orchestration_services(call_mcp_tool),
            ).orchestrate(
                slug,
                target_url=target_url,
                modules=modules,
                policy=profile,
                resume=bool(config.get("resume", False)),
                observations=config.get("observations"),
                approval=config.get("approval"),
                checkpoint_id=config.get("checkpoint_id", ""),
            )
        if session_id is not None:
            def bind_session(value):
                if isinstance(value, dict):
                    tool = str(value.get("tool", ""))
                    if tool.startswith("hunter_auto_") and tool != "hunter_auto_pentest":
                        value.setdefault("arguments", {}).setdefault(
                            "session_id",
                            session_id,
                        )
                    for child in value.values():
                        bind_session(child)
                elif isinstance(value, list):
                    for child in value:
                        bind_session(child)

            bind_session(result)
        return {
            "target_url": target_url,
            "workflow_slug": slug,
            "generation": generation,
            **result,
        }

    return await _async_workflow_result(
        "hunter_auto_pentest",
        orchestrate,
    )

@mcp.tool()
async def hunter_workflow_transition(case_slug: str, phase: str, deliverables: Optional[Dict[str, Any]] = None) -> str:
    return _workflow_result("hunter_workflow_transition", _workflow_kernel().transition, case_slug, phase, deliverables or {})

@mcp.tool()
async def hunter_workflow_checkpoint(case_slug: str, source_session: str = "") -> str:
    return _workflow_result("hunter_workflow_checkpoint", _workflow_kernel().checkpoint, case_slug, source_session)

@mcp.tool()
async def hunter_workflow_resume(case_slug: str, checkpoint_id: str = "") -> str:
    return _workflow_result("hunter_workflow_resume", _workflow_kernel().resume, case_slug, checkpoint_id)

@mcp.tool()
async def hunter_workflow_policy(case_slug: str, mode: str = "interactive", max_tool_calls: int = 8, max_escalation: int = 2, stop_on_proof: bool = True) -> str:
    policy = WorkflowPolicy(mode=mode, max_tool_calls=max_tool_calls, max_escalation=max_escalation, stop_on_proof=stop_on_proof)
    return _workflow_result("hunter_workflow_policy", _workflow_kernel().set_policy, case_slug, policy)

@mcp.tool()
async def hunter_hypothesis_add(case_slug: str, claim: str, confidence: float = 0.5, validation_step: Optional[Dict[str, Any]] = None, expected_revision: Optional[int] = None) -> str:
    return _workflow_result("hunter_hypothesis_add", _workflow_kernel().add_hypothesis, case_slug, claim, confidence, validation_step, expected_revision)

@mcp.tool()
async def hunter_evidence_register(case_slug: str, summary: str, source: str, path_or_url: str = "", evidence_type: str = "note", confidence: str = "medium", sha256: str = "") -> str:
    return _workflow_result("hunter_evidence_register", _workflow_kernel().register_evidence, case_slug, summary, source, path_or_url, evidence_type, confidence, sha256)

@mcp.tool()
async def hunter_finding_promote(case_slug: str, title: str, status: str, evidence_ids: List[str], severity: str = "Info", satisfies: Optional[List[str]] = None, proof_type: str = "") -> str:
    return _workflow_result("hunter_finding_promote", _workflow_kernel().promote_finding, case_slug, title, status, evidence_ids, severity, satisfies or [], proof_type)

@mcp.tool()
async def hunter_backend_status() -> str:
    return _workflow_result("hunter_backend_status", _workflow_kernel().backend_status)

@mcp.tool()
async def hunter_lane_catalog() -> str:
    return _workflow_result("hunter_lane_catalog", _workflow_kernel().lane_catalog)



def _tool_result_summary(payload: Dict[str, Any], fallback_name: str) -> str:
    tool = str(payload.get("tool") or fallback_name)
    status = str(payload.get("status") or "ok")
    data = payload.get("data")
    details = []
    if isinstance(data, dict):
        for key in ("returned", "count", "registered_tool_count"):
            if key in data:
                details.append(f"{key}={data[key]}")
        if data.get("path"):
            details.append(f"path={data['path']}")
    if payload.get("error"):
        details.append(f"error={payload['error']}")
    suffix = f" ({', '.join(details)})" if details else ""
    return f"{tool}: {status}{suffix}"


def _enable_structured_mcp_results() -> None:
    for tool_name, tool in mcp._tool_manager._tools.items():
        if not tool_name.startswith("hunter_"):
            continue
        original = tool.fn

        @functools.wraps(original)
        async def structured_tool(*args, __original=original, __name=tool_name, **kwargs):
            raw = await __original(*args, **kwargs)
            if not isinstance(raw, str):
                return raw
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError, json.JSONDecodeError):
                return raw
            if not isinstance(payload, dict):
                return raw
            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=_tool_result_summary(payload, __name),
                    )
                ],
                structuredContent=payload,
                isError=str(payload.get("status") or "").lower() == "error",
            )

        tool.fn = structured_tool
        tool.fn_metadata.output_schema = None
        tool.fn_metadata.output_model = None
        tool.fn_metadata.wrap_output = False


_enable_structured_mcp_results()


# ============================================================
# ReverseLab Tools Integration
# Merges reverse_lab_tools_mcp tools into hunter_tools MCP server.
# All reverse-engineering tools get "re_" prefix to avoid name collision.
# ============================================================

def _reverse_lab_tool_candidates(
    environment: Optional[Mapping[str, str]] = None,
) -> List[Path]:
    """Return configured ReverseLab MCP candidates in stable priority order."""
    env = os.environ if environment is None else environment
    raw_candidates = []
    explicit_path = env.get("REVERSELAB_MCP_PATH", "")
    try:
        explicit_candidate = (
            Path(explicit_path).expanduser()
            if explicit_path
            else None
        )
    except RuntimeError:
        explicit_candidate = None
    if explicit_candidate is not None and explicit_candidate.is_absolute():
        raw_candidates.append(explicit_candidate)
    for name in _REVERSE_LAB_ROOT_ENV_NAMES:
        root = env.get(name, "")
        try:
            root_path = Path(root).expanduser() if root else None
        except RuntimeError:
            root_path = None
        if root_path is not None and root_path.is_absolute():
            raw_candidates.append(
                root_path / _REVERSE_LAB_RELATIVE_PATH
            )

    candidates = []
    seen = set()
    for candidate in raw_candidates:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            candidates.append(resolved)
    return candidates


def _existing_extension_sources(tool_name: str) -> List[str]:
    sources = sorted(
        {
            str(source)
            for source, names in _EXTENSION_TOOL_SOURCES.items()
            if source != "reverse_lab_tools" and tool_name in names
        }
    )
    if tool_name.startswith("hunter_"):
        sources.append("hunter_core")
    if sources:
        return sorted(set(sources))
    return ["contract_extensions"]


def _classifier_extension_collisions() -> List[Dict[str, Any]]:
    """Return collision metadata in the shared classifier's legacy shape."""
    return [
        {
            "tool": collision["tool"],
            "sources": sorted(
                set(collision["existing_sources"])
                | {collision["incoming_source"]}
            ),
            "existing_source": collision["existing_sources"][0],
            "incoming_source": collision["incoming_source"],
        }
        for collision in _EXTENSION_TOOL_COLLISIONS
    ]


def _record_extension_tool_collision(
    tool_name: str,
    incoming_source: str,
) -> None:
    existing_sources = _existing_extension_sources(tool_name)
    record = {
        "tool": tool_name,
        "existing_sources": existing_sources,
        "incoming_source": incoming_source,
    }
    _clear_extension_tool_collision(tool_name, incoming_source)
    _EXTENSION_TOOL_COLLISIONS.append(record)
    _EXTENSION_TOOL_COLLISIONS.sort(
        key=lambda item: (
            item["tool"],
            item["existing_sources"],
            item["incoming_source"],
        )
    )


def _clear_extension_tool_collision(
    tool_name: str,
    incoming_source: str,
) -> None:
    _EXTENSION_TOOL_COLLISIONS[:] = [
        collision
        for collision in _EXTENSION_TOOL_COLLISIONS
        if not (
            collision.get("tool") == tool_name
            and collision.get("incoming_source") == incoming_source
        )
    ]


def _import_reverse_lab_tools() -> None:
    """Dynamically load reverse_lab_tools_mcp.py and merge its tools into hunter's mcp."""
    import importlib.util

    rlt_path = next(
        (
            path
            for path in _reverse_lab_tool_candidates()
            if path.is_file()
        ),
        None,
    )
    if rlt_path is None:
        print("[hunter_tools] reverse_lab_tools not found, skipping merge", file=sys.stderr)
        return
    rlt_path = rlt_path.resolve()

    module = _REVERSE_LAB_MODULE_CACHE.get(rlt_path)
    if module is None:
        path_digest = hashlib.sha256(
            os.path.normcase(str(rlt_path)).encode("utf-8")
        ).hexdigest()
        module_name = f"_hunter_reverselab_{path_digest}"
        original_sys_path = list(sys.path)
        project_dir = str(rlt_path.parent)
        try:
            if project_dir not in sys.path:
                sys.path.insert(0, project_dir)
            spec = importlib.util.spec_from_file_location(
                module_name,
                str(rlt_path),
            )
            if spec is None or spec.loader is None:
                print(
                    "[hunter_tools] failed to build reverselab spec",
                    file=sys.stderr,
                )
                return
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                if sys.modules.get(module_name) is module:
                    del sys.modules[module_name]
                print(
                    f"[hunter_tools] reverselab load failed: {exc}",
                    file=sys.stderr,
                )
                return
            _REVERSE_LAB_MODULE_CACHE[rlt_path] = module
        finally:
            sys.path[:] = original_sys_path

    rlt_mcp = getattr(module, "mcp", None)
    if rlt_mcp is None or not hasattr(rlt_mcp, "_tool_manager"):
        print("[hunter_tools] reverselab mcp missing _tool_manager", file=sys.stderr)
        return

    merged = 0
    source_tools = _EXTENSION_TOOL_SOURCES.setdefault(
        "reverse_lab_tools",
        set(),
    )
    for tool_name, tool in list(rlt_mcp._tool_manager._tools.items()):
        new_name = tool_name if tool_name.startswith("re_") else f"re_{tool_name}"
        if new_name in mcp._tool_manager._tools:
            existing_tool = mcp._tool_manager._tools[new_name]
            if (
                new_name not in source_tools
                or existing_tool is not tool
            ):
                _record_extension_tool_collision(
                    new_name,
                    "reverse_lab_tools",
                )
            continue
        _clear_extension_tool_collision(
            new_name,
            "reverse_lab_tools",
        )
        try:
            tool.name = new_name
        except Exception:
            pass
        mcp._tool_manager._tools[new_name] = tool
        source_tools.add(new_name)
        merged += 1
    print(f"[hunter_tools] merged {merged} reverse_lab tools (re_* prefix)", file=sys.stderr)


_import_reverse_lab_tools()


# ============================================================
# Entry Point
# ============================================================

def main():
    """Run MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
