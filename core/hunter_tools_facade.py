
"""ReverseLab-style facade for Hunter KB, payloads and Burp bridge.

This module is intentionally pure Python and side-effect light. MCP entrypoints
should be thin wrappers around this facade.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from payloads.loader import PayloadLoader
from core.burp_bridge import BurpBridge


HUNTER_ROOT = Path(__file__).resolve().parents[1]
PAYLOADS_DIR = HUNTER_ROOT / "payloads"


class HunterToolsFacade:
    """Unified tool facade that mirrors reverse_lab_tools conventions."""

    def __init__(self, hunter_root: Optional[str | Path] = None):
        self.hunter_root = Path(hunter_root).resolve() if hunter_root else HUNTER_ROOT
        self.payloads_dir = self.hunter_root / "payloads"
        self.payload_loader = PayloadLoader(str(self.payloads_dir))
        self.burp = BurpBridge()

    # ------------------------------------------------------------------
    # Envelope helpers
    # ------------------------------------------------------------------
    def ok(
        self,
        tool: str,
        data: Optional[Dict[str, Any]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        next_actions: Optional[List[str]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "tool": tool,
            "status": "ok",
            "data": data or {},
            "evidence": evidence or {},
            "next_actions": next_actions or [],
        }
        result.update(extra)
        return result

    def error(
        self,
        tool: str,
        exc: Exception | str,
        error_type: Optional[str] = None,
        hint: str = "",
        **extra: Any,
    ) -> Dict[str, Any]:
        if isinstance(exc, Exception):
            message = str(exc)
            etype = error_type or type(exc).__name__
        else:
            message = exc
            etype = error_type or "tool_error"
        result: Dict[str, Any] = {
            "tool": tool,
            "status": "error",
            "error": message,
            "error_type": etype,
        }
        if hint:
            result["hint"] = hint
        result.update(extra)
        return result

    # ------------------------------------------------------------------
    # KB inventory and search
    # ------------------------------------------------------------------
    def _relative_payload_path(self, path: Path) -> str:
        return path.resolve().relative_to(self.payloads_dir.resolve()).as_posix()

    def _markdown_files(self) -> List[Path]:
        return sorted(
            path for path in self.payloads_dir.rglob("*.md")
            if path.is_file() and "__pycache__" not in path.parts
        )

    def _payload_yaml_files(self) -> List[Path]:
        return sorted(
            path for path in self.payloads_dir.rglob("payloads.yaml")
            if path.is_file() and "__pycache__" not in path.parts
        )

    def _read_text_lossy(self, path: Path, max_chars: Optional[int] = None) -> str:
        text = path.read_text(encoding="utf-8", errors="replace")
        if max_chars is not None:
            return text[:max_chars]
        return text

    def _title_for_markdown(self, path: Path) -> str:
        try:
            for line in self._read_text_lossy(path, 2000).splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    return stripped.lstrip("#").strip()
        except OSError:
            pass
        return path.stem.replace("-", " ").title()

    def kb_list(self) -> Dict[str, Any]:
        try:
            markdown = [
                {
                    "path": self._relative_payload_path(path),
                    "title": self._title_for_markdown(path),
                    "size": path.stat().st_size,
                    "category": self._relative_payload_path(path).split("/", 1)[0],
                }
                for path in self._markdown_files()
            ]
            yaml_files = [
                {
                    "path": self._relative_payload_path(path),
                    "payload_type": path.parent.name,
                    "size": path.stat().st_size,
                }
                for path in self._payload_yaml_files()
            ]
            categories = sorted({item["category"] for item in markdown} | {item["payload_type"] for item in yaml_files})
            return self.ok(
                "hunter_kb_list",
                {
                    "root": str(self.payloads_dir),
                    "categories": categories,
                    "total_categories": len(categories),
                    "total_markdown": len(markdown),
                    "total_payload_yaml": len(yaml_files),
                    "markdown_files": markdown,
                    "payload_yaml_files": yaml_files,
                },
                evidence={"source": str(self.payloads_dir)},
                next_actions=["Use hunter_kb_search(query) to route signals", "Use hunter_kb_read(path) for exact technique content"],
            )
        except Exception as exc:  # pragma: no cover - defensive envelope
            return self.error("hunter_kb_list", exc)

    def _tokenize(self, text: str) -> List[str]:
        return [token.lower() for token in re.findall(r"[A-Za-z0-9_\-]+", text or "") if len(token) > 1]

    def _score_document(self, query_tokens: List[str], path: str, title: str, text: str) -> int:
        haystack = f"{path}\n{title}\n{text}".lower()
        counts = Counter(self._tokenize(haystack))
        score = 0
        path_lower = path.lower()
        title_lower = title.lower()
        for token in query_tokens:
            token_l = token.lower()
            score += counts.get(token_l, 0)
            if token_l in path_lower:
                score += 8
            if token_l in title_lower:
                score += 5
            if token_l in haystack:
                score += 1
        return score

    def _snippets(self, text: str, query_tokens: List[str], max_snippets: int = 3) -> List[str]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        snippets: List[str] = []
        for line in lines:
            lower = line.lower()
            if any(token in lower for token in query_tokens):
                snippets.append(line[:240])
                if len(snippets) >= max_snippets:
                    break
        if not snippets and lines:
            snippets.append(lines[0][:240])
        return snippets

    def kb_search(self, query: str, limit: int = 20) -> Dict[str, Any]:
        try:
            limit = max(1, min(int(limit), 100))
            query_tokens = self._tokenize(query)
            if not query_tokens:
                return self.error("hunter_kb_search", "query is required", "invalid_input")

            hits: List[Dict[str, Any]] = []
            searched = 0
            for path in self._markdown_files():
                rel = self._relative_payload_path(path)
                text = self._read_text_lossy(path)
                title = self._title_for_markdown(path)
                score = self._score_document(query_tokens, rel, title, text)
                searched += 1
                if score > 0:
                    hits.append({
                        "kind": "markdown",
                        "board": "hunter",
                        "path": rel,
                        "title": title,
                        "category": rel.split("/", 1)[0],
                        "score": score,
                        "snippets": self._snippets(text, query_tokens),
                    })

            for path in self._payload_yaml_files():
                rel = self._relative_payload_path(path)
                text = self._read_text_lossy(path)
                score = self._score_document(query_tokens, rel, path.parent.name, text)
                searched += 1
                if score > 0:
                    hits.append({
                        "kind": "payload_yaml",
                        "board": "hunter",
                        "path": rel,
                        "title": f"{path.parent.name} payloads",
                        "category": path.parent.name,
                        "score": score,
                        "snippets": self._snippets(text, query_tokens),
                    })

            hits.sort(key=lambda item: (-item["score"], item["path"]))
            returned = hits[:limit]
            return self.ok(
                "hunter_kb_search",
                {
                    "query": query,
                    "board": "hunter",
                    "returned": len(returned),
                    "total": len(hits),
                    "results": returned,
                    "by_board": {"hunter": returned},
                    "top": returned[: min(5, len(returned))],
                },
                evidence={"searched_files": searched, "payloads_dir": str(self.payloads_dir)},
                next_actions=["Read the top hit with hunter_kb_read", "Pair KB hits with hunter_payload_search for concrete payloads"],
            )
        except Exception as exc:  # pragma: no cover
            return self.error("hunter_kb_search", exc)

    def _resolve_kb_path(self, technique_path: str) -> Path:
        if not technique_path:
            raise ValueError("technique_path is required")
        normalized = technique_path.replace("\\", "/").lstrip("/")
        candidate = (self.payloads_dir / normalized).resolve()
        root = self.payloads_dir.resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("technique_path must stay under payloads/")
        if not candidate.is_file():
            raise FileNotFoundError(normalized)
        if candidate.suffix.lower() not in {".md", ".yaml", ".yml"}:
            raise ValueError("only .md/.yaml/.yml Hunter KB files are readable")
        return candidate

    def kb_read(self, technique_path: str, max_chars: int = 12000) -> Dict[str, Any]:
        try:
            max_chars = max(1, min(int(max_chars), 200000))
            path = self._resolve_kb_path(technique_path)
            text = self._read_text_lossy(path)
            content = text[:max_chars]
            rel = self._relative_payload_path(path)
            return self.ok(
                "hunter_kb_read",
                {
                    "board": "hunter",
                    "path": rel,
                    "absolute_path": str(path),
                    "size": path.stat().st_size,
                    "lines": text.count("\n") + 1 if text else 0,
                    "content": content,
                    "truncated": len(text) > len(content),
                },
                evidence={"source_file": str(path)},
                next_actions=["Use this technique with hunter_payload_generate or a Burp bridge plan"],
            )
        except Exception as exc:
            return self.error("hunter_kb_read", exc)

    # ------------------------------------------------------------------
    # Payload helper search for recommendations
    # ------------------------------------------------------------------
    def payload_search(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        try:
            return self.payload_loader.search(keyword)[: max(1, min(int(limit), 100))]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Burp bridge wrappers
    # ------------------------------------------------------------------
    def _burp_plan(self, tool: str, action: Dict[str, Any], action_name: str) -> Dict[str, Any]:
        return self.ok(
            tool,
            {
                "bridge": "burp",
                "mode": "action_descriptor",
                "action_name": action_name,
                "action": action,
            },
            evidence={"source": "core.burp_bridge.BurpBridge"},
            next_actions=[
                "Execute this plan with the matching Burp MCP tool if available",
                "Import resulting request/response/screenshot with hunter_burp_import",
            ],
        )

    def burp_bridge(self, action: str, **kwargs: Any) -> Dict[str, Any]:
        try:
            action_key = (action or "").strip().lower().replace("-", "_")
            mapping = {
                "request": (self.burp.send_request, {"url", "method", "headers", "body", "http2"}),
                "send_request": (self.burp.send_request, {"url", "method", "headers", "body", "http2"}),
                "repeater": (self.burp.create_repeater, {"url", "method", "headers", "body", "tab_name", "http2"}),
                "create_repeater": (self.burp.create_repeater, {"url", "method", "headers", "body", "tab_name", "http2"}),
                "intruder": (self.burp.send_to_intruder, {"url", "method", "headers", "body", "tab_name"}),
                "proxy_history": (self.burp.get_proxy_history, {"count", "offset"}),
                "proxy_search": (self.burp.search_proxy_history, {"regex", "count", "offset"}),
                "scanner_issues": (self.burp.get_scanner_issues, {"count", "offset", "severity_filter"}),
                "collaborator_generate": (self.burp.collaborator_generate, {"context"}),
                "collaborator_check": (self.burp.collaborator_check, {"payload_id"}),
                "websocket_history": (self.burp.get_websocket_history, {"count", "offset"}),
                "websocket_search": (self.burp.search_websocket_history, {"regex", "count", "offset"}),
                "param_miner": (self.burp.param_miner_workflow, {"url", "method", "headers", "body"}),
                "jwt_plugin": (self.burp.plugin_jwt_analysis, {"url", "method", "headers", "body", "jwt_token"}),
            }
            entry = mapping.get(action_key)
            if not entry:
                return self.error(
                    "hunter_burp_bridge",
                    f"unknown burp bridge action: {action}",
                    "invalid_input",
                    hint=f"valid actions: {', '.join(sorted(mapping))}",
                )
            func, allowed = entry
            filtered = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
            result = func(**filtered)
            return self._burp_plan("hunter_burp_bridge", result, action_key)
        except Exception as exc:
            return self.error("hunter_burp_bridge", exc)

    def burp_repeater(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        tab_name: str = "",
        http2: bool = True,
    ) -> Dict[str, Any]:
        try:
            action = self.burp.create_repeater(url, method=method, headers=headers or {}, body=body, tab_name=tab_name, http2=http2)
            return self._burp_plan("hunter_burp_repeater", action, "repeater")
        except Exception as exc:
            return self.error("hunter_burp_repeater", exc)

    def burp_proxy_search(self, regex: str, count: int = 50, offset: int = 0) -> Dict[str, Any]:
        try:
            action = self.burp.search_proxy_history(regex, count=count, offset=offset)
            return self._burp_plan("hunter_burp_proxy_search", action, "proxy_search")
        except Exception as exc:
            return self.error("hunter_burp_proxy_search", exc)

    def burp_scanner_issues(self, count: int = 50, offset: int = 0, severity_filter: str = "") -> Dict[str, Any]:
        try:
            action = self.burp.get_scanner_issues(count=count, offset=offset, severity_filter=severity_filter)
            return self._burp_plan("hunter_burp_scanner_issues", action, "scanner_issues")
        except Exception as exc:
            return self.error("hunter_burp_scanner_issues", exc)

    def burp_collaborator_workflow(
        self,
        workflow: str,
        url: str,
        param: str = "",
        method: str = "GET",
        template: str = "",
    ) -> Dict[str, Any]:
        try:
            workflow_key = (workflow or "").strip().lower().replace("-", "_")
            if workflow_key == "blind_ssrf":
                plan = self.burp.blind_ssrf_workflow(url, param=param or "url", method=method)
            elif workflow_key == "blind_xxe":
                plan = self.burp.blind_xxe_workflow(url, param=param, method=method, template=template)
            elif workflow_key in {"blind_cmd", "blind_cmdi", "blind_command"}:
                plan = self.burp.blind_cmdi_workflow(url, param=param or "ip", method=method)
                workflow_key = "blind_cmdi"
            else:
                return self.error(
                    "hunter_burp_collaborator_workflow",
                    f"unknown collaborator workflow: {workflow}",
                    "invalid_input",
                    hint="valid workflows: blind_ssrf, blind_xxe, blind_cmdi",
                )
            return self.ok(
                "hunter_burp_collaborator_workflow",
                {"workflow": workflow_key, "plan": plan},
                evidence={"source": "core.burp_bridge.BurpBridge"},
                next_actions=[
                    "Generate the Collaborator payload with Burp MCP",
                    "Use the payload in the injection point",
                    "Check interactions and import proof with hunter_burp_import",
                ],
            )
        except Exception as exc:
            return self.error("hunter_burp_collaborator_workflow", exc)

    # ------------------------------------------------------------------
    # Capabilities / health / routing
    # ------------------------------------------------------------------
    def _tool_recommendations(self, raw: str) -> List[Dict[str, Any]]:
        text = (raw or "").lower()
        recs: List[Dict[str, Any]] = []

        def add(tool: str, reason: str, priority: int):
            if not any(item["tool"] == tool for item in recs):
                recs.append({"tool": tool, "reason": reason, "priority": priority})

        if any(token in text for token in ["idor", "userid", "user_id", "object", "authorization", "x-id-token"]):
            add("hunter_auto_idor", "object or authorization boundary signal", 10)
            add("hunter_auto_access_control", "compare role/token access matrix", 9)
            add("hunter_burp_repeater", "manual differential proof in Repeater", 8)
        if any(token in text for token in ["jwt", "token", "bearer", "kid", "alg"]):
            add("hunter_auto_jwt", "JWT/token validation signal", 9)
            add("hunter_burp_proxy_search", "mine proxy history for token-bearing requests", 6)
        if "cors" in text or "origin" in text:
            add("hunter_auto_cors", "CORS/Origin validation signal", 8)
        if "ssrf" in text or "metadata" in text or "url=" in text:
            add("hunter_auto_ssrf", "SSRF URL/callback signal", 8)
            add("hunter_burp_collaborator_workflow", "OOB proof workflow", 7)
        if "xxe" in text or "doctype" in text or "xml" in text:
            add("hunter_auto_xxe", "XML parser signal", 8)
            add("hunter_burp_collaborator_workflow", "blind XXE OOB proof", 7)
        if "sqli" in text or "sql" in text or "union" in text:
            add("hunter_auto_sqli", "SQL injection signal", 6)
        if "xss" in text or "script" in text or "innerhtml" in text:
            add("hunter_auto_xss", "XSS sink/reflection signal", 6)
        if "graphql" in text:
            add("hunter_auto_graphql", "GraphQL endpoint signal", 6)
        if "websocket" in text or "wss://" in text or "ws://" in text:
            add("hunter_auto_websocket", "WebSocket endpoint signal", 6)
        if "race" in text or "coupon" in text or "balance" in text or "payment" in text:
            add("hunter_auto_race", "state-changing concurrency signal", 7)
        if "cmd" in text or "command" in text or "whoami" in text:
            add("hunter_auto_cmd", "command injection signal", 6)
        if "ssti" in text or "template" in text or "jinja" in text:
            add("hunter_auto_ssti", "template injection signal", 6)
        if not recs:
            add("hunter_recon", "no specific vuln signal; establish baseline", 1)
        return sorted(recs, key=lambda item: item["priority"], reverse=True)

    def kb_recommend(
        self,
        signals: Optional[List[str]] = None,
        finding: str = "",
        target: str = "",
        limit: int = 8,
    ) -> Dict[str, Any]:
        try:
            raw = " ".join((signals or []) + [finding or "", target or ""]).strip()
            query = raw or "web vulnerability recon"
            kb = self.kb_search(query, limit=limit)
            kb_hits = kb.get("data", {}).get("results", []) if kb.get("status") == "ok" else []
            keyword_tokens = self._tokenize(query)
            payload_hits: List[Dict[str, Any]] = []
            for token in keyword_tokens:
                if len(payload_hits) >= limit:
                    break
                for hit in self.payload_search(token, limit=limit):
                    hit_key = (hit.get("type"), hit.get("section"), hit.get("payload"))
                    if not any((h.get("type"), h.get("section"), h.get("payload")) == hit_key for h in payload_hits):
                        payload_hits.append(hit)
                    if len(payload_hits) >= limit:
                        break
            tool_recs = self._tool_recommendations(query)
            burp_actions = [
                rec for rec in tool_recs
                if rec["tool"].startswith("hunter_burp")
            ]
            if not burp_actions and any(rec["tool"].startswith("hunter_auto") for rec in tool_recs):
                burp_actions.append({
                    "tool": "hunter_burp_repeater",
                    "reason": "manual request diff proof for top Hunter auto finding",
                    "priority": 5,
                })
            return self.ok(
                "hunter_kb_recommend",
                {
                    "target": target,
                    "signals": signals or [],
                    "finding": finding,
                    "kb_hits": kb_hits,
                    "payload_hits": payload_hits,
                    "tool_recommendations": tool_recs,
                    "burp_actions": burp_actions,
                },
                evidence={"query": query, "kb_total": kb.get("data", {}).get("total", 0)},
                next_actions=[
                    "Read top KB hit",
                    "Generate or select payloads",
                    "Build a Burp Repeater/Collaborator plan for proof",
                ],
            )
        except Exception as exc:
            return self.error("hunter_kb_recommend", exc)

    def health(self) -> Dict[str, Any]:
        kb = self.kb_list()
        data = kb.get("data", {}) if kb.get("status") == "ok" else {}
        payload_types: List[str] = []
        try:
            payload_types = self.payload_loader.list_types()
        except Exception:
            payload_types = []
        return self.ok(
            "hunter_tools_health",
            {
                "server_name": "hunter_tools",
                "tool_style": "reverse_lab_tools-compatible",
                "hunter_root": str(self.hunter_root),
                "python": {"executable": sys.executable, "version": sys.version.split()[0]},
                "kb": {
                    "root": str(self.payloads_dir),
                    "total_markdown": data.get("total_markdown", 0),
                    "total_payload_yaml": data.get("total_payload_yaml", 0),
                    "categories": data.get("categories", []),
                },
                "payloads": {"types": payload_types, "total_types": len(payload_types)},
            },
            evidence={"kb_list_status": kb.get("status")},
        )

    def capabilities(self) -> Dict[str, Any]:
        tools = {
            "hunter_kb_list": {"category": "kb", "description": "List Hunter markdown techniques and YAML payload files"},
            "hunter_kb_search": {"category": "kb", "description": "Search Hunter KB by signal/query"},
            "hunter_kb_read": {"category": "kb", "description": "Read a Hunter KB file under payloads/"},
            "hunter_kb_recommend": {"category": "kb", "description": "Combine KB, payload and tool recommendations"},
            "hunter_burp_bridge": {"category": "burp-bridge", "description": "Generic Burp MCP action descriptor builder"},
            "hunter_burp_repeater": {"category": "burp-bridge", "description": "Build a Burp Repeater action descriptor"},
            "hunter_burp_proxy_search": {"category": "burp-bridge", "description": "Build a Proxy history regex search action"},
            "hunter_burp_scanner_issues": {"category": "burp-bridge", "description": "Build a Scanner issues retrieval action"},
            "hunter_burp_collaborator_workflow": {"category": "burp-bridge", "description": "Build SSRF/XXE/CMDI Collaborator workflow plans"},
        }
        return self.ok(
            "hunter_tools_capabilities",
            {
                "server_name": "hunter_tools",
                "tool_style": "reverse_lab_tools-compatible",
                "return_style": "dict for hunter_tools_mcp, JSON string for legacy mcp_server compatibility",
                "tools": tools,
                "workflow": [
                    "hunter_kb_search(query)",
                    "hunter_kb_read(path)",
                    "hunter_kb_recommend(signals, finding)",
                    "hunter_burp_repeater/proxy_search/collaborator_workflow",
                    "hunter_burp_import for evidence packaging",
                ],
            },
        )
