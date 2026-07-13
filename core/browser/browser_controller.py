"""Build or execute auditable Playwright MCP browser operations."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping
from urllib.parse import urlparse


PLAYWRIGHT_BACKEND = "playwright-mcp"
PLAYWRIGHT_MODE = "external-mcp-handoff"
HOOK_PREFIX = "__HUNTER_HOOK__"

CallMCPTool = Callable[
    [str, str, Dict[str, Any]],
    Awaitable[Dict[str, Any]],
]


def _call(tool: str, **arguments: Any) -> Dict[str, Any]:
    return {"tool": tool, "arguments": arguments}


def _hunter_call(tool: str, **arguments: Any) -> Dict[str, Any]:
    return {
        "backend": "hunter_tools",
        "tool": tool,
        "arguments": arguments,
        "execution": "deferred",
        "status": "proposed",
        "requires_confirmation": True,
    }


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _normalized(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def _css_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _error_status(error: str) -> str:
    normalized = str(error or "").casefold()
    timeout_markers = ("timeout", "timed out", "deadline exceeded", "gateway timeout")
    return "timeout" if any(marker in normalized for marker in timeout_markers) else "error"


def _result_text(result: Any) -> str:
    if isinstance(result, str):
        return result.strip()
    if isinstance(result, Mapping):
        for key in ("error", "message", "detail", "text"):
            value = result.get(key)
            if value:
                return str(value).strip()
        for key in ("content", "structuredContent", "data", "result", "value"):
            nested = result.get(key)
            text = _result_text(nested)
            if text:
                return text
    if isinstance(result, list):
        for item in result:
            text = _result_text(item)
            if text:
                return text
    return ""


def _result_error(result: Any, depth: int = 0) -> str:
    if not isinstance(result, Mapping):
        return ""
    status = str(result.get("status", "")).casefold()
    error = result.get("error")
    if error or result.get("isError") is True or status in {
        "error",
        "failed",
        "failure",
        "timeout",
        "cancelled",
        "canceled",
    }:
        return str(
            error
            or _result_text(result)
            or status
        )
    if depth < 6:
        for key in ("structuredContent", "data", "result", "value"):
            nested = result.get(key)
            nested_error = _result_error(nested, depth + 1)
            if nested_error:
                return nested_error
    return ""


def _json_mapping_from_text(value: str) -> Dict[str, Any]:
    text = str(value or "").strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]).strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    return dict(parsed) if isinstance(parsed, Mapping) else {}


def _structured_mapping(value: Any, depth: int = 0) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    if depth >= 8:
        return dict(value)
    for key in ("structuredContent", "data", "result", "value"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            return _structured_mapping(nested, depth + 1)
        if isinstance(nested, str):
            parsed = _json_mapping_from_text(nested)
            if parsed:
                return _structured_mapping(parsed, depth + 1)
    content = value.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, Mapping):
                parsed = _json_mapping_from_text(item.get("text", ""))
                if parsed:
                    return _structured_mapping(parsed, depth + 1)
            elif isinstance(item, str):
                parsed = _json_mapping_from_text(item)
                if parsed:
                    return _structured_mapping(parsed, depth + 1)
    return dict(value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"", "0", "false", "no", "off", "none", "null"}:
            return False
        if normalized in {"1", "true", "yes", "on"}:
            return True
    return bool(value)


def _url_identity(value: str) -> tuple[str, str, int | None, str, str]:
    parsed = urlparse(str(value or "").strip())
    scheme = parsed.scheme.casefold()
    hostname = (parsed.hostname or "").casefold()
    port = parsed.port
    if port is None:
        port = 443 if scheme in {"https", "wss"} else 80 if scheme in {"http", "ws"} else None
    return (scheme, hostname, port, parsed.path or "/", parsed.query)


class ExecutionAdapter:
    """Forward browser descriptors to an injected MCP tool caller."""

    def __init__(self, call_mcp_tool: CallMCPTool) -> None:
        self.call_mcp_tool = call_mcp_tool

    async def execute_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        try:
            result = await self.call_mcp_tool(
                PLAYWRIGHT_BACKEND,
                str(tool_name),
                dict(arguments or {}),
            )
            if isinstance(result, Mapping):
                return dict(result)
            return {"result": result}
        except Exception as exc:
            message = str(exc).strip() or type(exc).__name__
            return {"error": message}

    async def _execute_failure_calls(
        self,
        plan: Mapping[str, Any],
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for call in plan.get("on_failure", []) or []:
            tool_name = str(call.get("tool", ""))
            result = await self.execute_call(
                tool_name,
                call.get("arguments", {}),
            )
            results.append({"tool": tool_name, "result": result})
        return results

    async def execute_plan(self, plan: Mapping[str, Any]) -> Dict[str, Any]:
        merged = dict(plan)
        results: List[Dict[str, Any]] = []
        for call in plan.get("calls", []) or []:
            tool_name = str(call.get("tool", ""))
            arguments = dict(call.get("arguments", {}) or {})
            result = await self.execute_call(tool_name, arguments)
            results.append({"tool": tool_name, "result": result})
            error = _result_error(result)
            if error:
                failure_results = await self._execute_failure_calls(plan)
                merged.update(
                    {
                        "status": _error_status(error),
                        "execution": "failed",
                        "execution_results": results,
                        "failure_results": failure_results,
                        "error": error,
                    }
                )
                return merged
        merged.update(
            {
                "status": "ok",
                "execution": "completed",
                "execution_results": results,
            }
        )
        return merged


class _ControlParser(HTMLParser):
    """Collect enough semantic HTML state to propose locator fallbacks."""

    CONTROL_TAGS = {"a", "button", "form", "input", "label", "option", "select", "textarea"}
    VOID_TAGS = {"input"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.nodes: List[Dict[str, Any]] = []
        self._open_nodes: List[int] = []
        self._form_stack: List[int] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: List[tuple[str, str | None]],
    ) -> None:
        lowered = tag.casefold()
        if lowered not in self.CONTROL_TAGS:
            return
        attributes = {str(key).casefold(): value or "" for key, value in attrs}
        node = {
            "tag": lowered,
            "attrs": attributes,
            "text_parts": [],
            "form_index": self._form_stack[-1] if self._form_stack else None,
        }
        index = len(self.nodes)
        self.nodes.append(node)
        if lowered not in self.VOID_TAGS:
            self._open_nodes.append(index)
        if lowered == "form":
            self._form_stack.append(index)

    def handle_startendtag(
        self,
        tag: str,
        attrs: List[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if not data.strip():
            return
        for index in self._open_nodes:
            self.nodes[index]["text_parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        for position in range(len(self._open_nodes) - 1, -1, -1):
            index = self._open_nodes[position]
            if self.nodes[index]["tag"] != lowered:
                continue
            del self._open_nodes[position:]
            if lowered == "form" and self._form_stack:
                self._form_stack.pop()
            break


class ElementLocator:
    """Derive ordered Playwright locator strategies from static HTML."""

    _ROLE_TAGS = {
        "button": {"button"},
        "checkbox": {"input"},
        "combobox": {"select"},
        "link": {"a"},
        "textbox": {"input", "textarea"},
    }

    def __init__(self, html: str) -> None:
        parser = _ControlParser()
        parser.feed(str(html or ""))
        parser.close()
        self.nodes = parser.nodes
        self._labels = self._build_label_map()

    def _build_label_map(self) -> Dict[str, str]:
        labels: Dict[str, str] = {}
        for node in self.nodes:
            if node["tag"] != "label":
                continue
            target = node["attrs"].get("for", "")
            text = self._node_text(node)
            if target and text:
                labels[target] = text
        return labels

    @staticmethod
    def _node_text(node: Mapping[str, Any]) -> str:
        return re.sub(r"\s+", " ", "".join(node.get("text_parts", []))).strip()

    @staticmethod
    def _node_role(node: Mapping[str, Any]) -> str:
        attrs = node["attrs"]
        explicit = attrs.get("role", "")
        if explicit:
            return explicit.casefold()
        tag = node["tag"]
        input_type = attrs.get("type", "text").casefold()
        if tag == "button" or (tag == "input" and input_type in {"button", "submit", "reset"}):
            return "button"
        if tag == "a" and attrs.get("href"):
            return "link"
        if tag == "select":
            return "combobox"
        if tag == "textarea" or (tag == "input" and input_type not in {"checkbox", "radio", "hidden"}):
            return "textbox"
        if tag == "input" and input_type in {"checkbox", "radio"}:
            return input_type
        return ""

    @staticmethod
    def _matches(value: Any, query: str) -> bool:
        candidate = _normalized(value)
        return bool(candidate and (candidate == query or query in candidate))

    def _role_matches(self, node: Mapping[str, Any], role: str | None) -> bool:
        if not role:
            return True
        normalized_role = role.casefold()
        if self._node_role(node) == normalized_role:
            return True
        return node["tag"] in self._ROLE_TAGS.get(normalized_role, set())

    @staticmethod
    def _css_for(node: Mapping[str, Any]) -> str:
        tag = str(node["tag"])
        attrs = node["attrs"]
        if attrs.get("id"):
            return f'#{_css_escape(attrs["id"])}'
        if attrs.get("name"):
            return f'{tag}[name="{_css_escape(attrs["name"])}"]'
        if attrs.get("type"):
            return f'{tag}[type="{_css_escape(attrs["type"])}"]'
        if attrs.get("aria-label"):
            return f'{tag}[aria-label="{_css_escape(attrs["aria-label"])}"]'
        return tag

    @staticmethod
    def _candidate(strategy: str, playwright: str, **details: Any) -> Dict[str, Any]:
        return {"strategy": strategy, "playwright": playwright, **details}

    def locate(
        self,
        query: str,
        role: str | None = None,
        selector: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Return deterministic locator fallbacks without executing them."""

        raw_query = str(query or "").strip()
        normalized_query = _normalized(raw_query)
        explicit = str(selector or "").strip()
        if not explicit and (
            raw_query.startswith(("#", ".", "[", "/", "(", "xpath="))
        ):
            explicit = raw_query
        candidates: List[Dict[str, Any]] = []

        if explicit:
            strategy = (
                "xpath"
                if explicit.startswith(("/", "(", "xpath="))
                else "css"
            )
            prefix = (
                "xpath="
                if strategy == "xpath" and not explicit.startswith("xpath=")
                else ""
            )
            candidates.append(
                self._candidate(
                    strategy,
                    f"page.locator({_json(prefix + explicit)})",
                    selector=explicit,
                )
            )

        matching_nodes = [
            node
            for node in self.nodes
            if self._role_matches(node, role)
            and (
                self._matches(self._node_text(node), normalized_query)
                or self._matches(node["attrs"].get("aria-label"), normalized_query)
                or self._matches(node["attrs"].get("placeholder"), normalized_query)
                or self._matches(node["attrs"].get("name"), normalized_query)
                or self._matches(node["attrs"].get("id"), normalized_query)
                or self._matches(
                    self._labels.get(node["attrs"].get("id", "")),
                    normalized_query,
                )
            )
        ]

        for node in matching_nodes:
            text = self._node_text(node)
            node_role = role or self._node_role(node)
            if text and self._matches(text, normalized_query):
                if node_role:
                    playwright = (
                        f"page.getByRole({_json(node_role)}, "
                        f"{{name: {_json(text)}, exact: true}})"
                    )
                else:
                    playwright = f"page.getByText({_json(text)}, {{exact: true}})"
                candidates.append(self._candidate("text", playwright, text=text))

        for node in matching_nodes:
            aria_label = node["attrs"].get("aria-label", "")
            if aria_label and self._matches(aria_label, normalized_query):
                candidates.append(
                    self._candidate(
                        "aria-label",
                        f"page.getByLabel({_json(aria_label)})",
                        value=aria_label,
                    )
                )

        for node in matching_nodes:
            attrs = node["attrs"]
            input_type = attrs.get("type", "").casefold()
            if (
                node.get("form_index") is not None
                and self._node_role(node) == "button"
                and (node["tag"] == "button" or input_type == "submit")
            ):
                name = self._node_text(node) or attrs.get("aria-label") or raw_query
                candidates.append(
                    self._candidate(
                        "context-submit",
                        f'page.locator("form").getByRole("button", '
                        f"{{name: {_json(name)}}})",
                        form=True,
                    )
                )

        for node in matching_nodes:
            name = node["attrs"].get("name", "")
            if name and self._matches(name, normalized_query):
                selector_value = f'[name="{_css_escape(name)}"]'
                candidates.append(
                    self._candidate(
                        "name",
                        f"page.locator({_json(selector_value)})",
                        value=name,
                    )
                )

        for node in matching_nodes:
            placeholder = node["attrs"].get("placeholder", "")
            if placeholder and self._matches(placeholder, normalized_query):
                candidates.append(
                    self._candidate(
                        "placeholder",
                        f"page.getByPlaceholder({_json(placeholder)})",
                        value=placeholder,
                    )
                )

        for node in matching_nodes:
            node_id = node["attrs"].get("id", "")
            label = self._labels.get(node_id, "")
            if label and self._matches(label, normalized_query):
                candidates.append(
                    self._candidate(
                        "label",
                        f"page.getByLabel({_json(label)})",
                        value=label,
                    )
                )

        for node in matching_nodes:
            css = self._css_for(node)
            candidates.append(
                self._candidate(
                    "css",
                    f"page.locator({_json(css)})",
                    selector=css,
                )
            )

        deduplicated: List[Dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in candidates:
            key = (candidate["strategy"], candidate["playwright"])
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(candidate)
        return deduplicated

    def locate_with_failure_plan(
        self,
        query: str,
        role: str | None = None,
        selector: str | None = None,
    ) -> Dict[str, Any]:
        locators = self.locate(query, role=role, selector=selector)
        if locators:
            return {"status": "found", "locators": locators, "failure_calls": []}
        return {
            "status": "not-found",
            "locators": [],
            "failure_calls": BrowserController.failure_calls("locator"),
        }


class BrowserController:
    """Compose auditable Playwright MCP descriptors and deferred Hunter routes."""

    def __init__(
        self,
        artifact_dir: str | Path | None = None,
        attack_session: Any | None = None,
        call_mcp_tool: CallMCPTool | None = None,
    ) -> None:
        self.artifact_dir = Path(artifact_dir).resolve() if artifact_dir else None
        self.attack_session = attack_session
        self.execution_adapter = (
            ExecutionAdapter(call_mcp_tool) if call_mcp_tool is not None else None
        )

    @staticmethod
    def _absolute_url(url: str, schemes: Iterable[str] = ("http", "https")) -> str:
        parsed = urlparse(str(url or "").strip())
        if parsed.scheme.casefold() not in set(schemes) or not parsed.netloc:
            allowed = ", ".join(sorted(schemes))
            raise ValueError(f"URL must be absolute and use one of: {allowed}")
        return parsed.geturl()

    def _authorize(self, method: str, url: str) -> str:
        normalized = self._absolute_url(url)
        if self.attack_session is not None:
            self.attack_session.authorize_request(method.upper(), normalized)
        return normalized

    def _authorize_websocket(self, url: str) -> str:
        normalized = self._absolute_url(url, schemes=("ws", "wss"))
        if self.attack_session is not None:
            parsed = urlparse(normalized)
            mapped = parsed._replace(scheme="https" if parsed.scheme == "wss" else "http")
            self.attack_session.authorize_request("GET", mapped.geturl())
        return normalized

    @staticmethod
    def failure_calls(label: str = "browser") -> List[Dict[str, Any]]:
        safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(label)).strip("-") or "browser"
        return [
            _call("browser_take_screenshot", filename=f"hunter-{safe_label}-failure.png"),
            _call("browser_snapshot"),
            _call("browser_console_messages", level="error"),
        ]

    def _plan(
        self,
        operation: str,
        calls: Iterable[Dict[str, Any]],
        **metadata: Any,
    ) -> Dict[str, Any]:
        return {
            "backend": PLAYWRIGHT_BACKEND,
            "mode": PLAYWRIGHT_MODE,
            "status": "proposed",
            "execution": "deferred",
            "requires_confirmation": False,
            "operation": operation,
            "artifact_dir": str(self.artifact_dir) if self.artifact_dir else "",
            "calls": list(calls),
            "on_failure": self.failure_calls(operation),
            **metadata,
        }

    @staticmethod
    def _run_code(code: str, **arguments: Any) -> Dict[str, Any]:
        return _call("browser_run_code", code=code, **arguments)

    def _maybe_execute(
        self,
        plan: Dict[str, Any],
        execute: bool,
        executor: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]] | None = None,
    ) -> Any:
        if not execute or self.execution_adapter is None:
            return plan
        return (executor or self.execution_adapter.execute_plan)(plan)

    def execute_plan(
        self,
        plan: Dict[str, Any],
        execute: bool = False,
    ) -> Any:
        return self._maybe_execute(plan, execute)

    @staticmethod
    def _navigation_summary_code() -> str:
        return (
            "() => {\n"
            "  const root = document.documentElement;\n"
            "  const html = root ? root.outerHTML : '';\n"
            "  const loginSelector = [\n"
            "    'input[type=\"password\"]',\n"
            "    'input[autocomplete=\"current-password\"]',\n"
            "    'form[action*=\"login\" i]',\n"
            "    'form[action*=\"signin\" i]'\n"
            "  ].join(',');\n"
            "  const sockets = window.__hunterWebSockets;\n"
            "  const hookSockets = Array.isArray(sockets)\n"
            "    ? sockets.length > 0\n"
            "    : Boolean(sockets && Object.keys(sockets).length);\n"
            "  const performanceSockets = typeof performance !== 'undefined'\n"
            "    && performance.getEntries().some(entry => /^wss?:/i.test(entry.name || ''));\n"
            "  return {\n"
            "    url: window.location.href,\n"
            "    title: document.title || '',\n"
            "    html_length: html.length,\n"
            "    has_form: Boolean(document.querySelector('form')),\n"
            "    has_login: Boolean(document.querySelector(loginSelector)),\n"
            "    has_websocket: Boolean(hookSockets || performanceSockets)\n"
            "  };\n"
            "}"
        )

    async def _execute_navigation(
        self,
        plan: Dict[str, Any],
    ) -> Dict[str, Any]:
        assert self.execution_adapter is not None
        result = await self.execution_adapter.execute_plan(plan)
        defaults = {
            "url": str(plan.get("target_url", "")),
            "title": "",
            "html_length": 0,
            "has_form": False,
            "has_login": False,
            "has_websocket": False,
        }
        if result.get("status") != "ok":
            result.update(defaults)
            return result

        summary_result = await self.execution_adapter.execute_call(
            "browser_evaluate",
            {"function": self._navigation_summary_code()},
        )
        result.setdefault("execution_results", []).append(
            {"tool": "browser_evaluate", "result": summary_result}
        )
        summary_error = _result_error(summary_result)
        if summary_error:
            error = summary_error
            result.update(
                {
                    **defaults,
                    "status": _error_status(error),
                    "execution": "failed",
                    "error": error,
                }
            )
            return result

        summary = _structured_mapping(summary_result)
        summary_keys = {
            "url",
            "title",
            "html_length",
            "has_form",
            "has_login",
            "has_websocket",
        }
        if not summary_keys.intersection(summary):
            error = "navigation summary was not returned by browser_evaluate"
            result.update(
                {
                    **defaults,
                    "status": "error",
                    "execution": "failed",
                    "error": error,
                }
            )
            return result
        try:
            html_length = max(0, int(summary.get("html_length", 0)))
        except (TypeError, ValueError):
            html_length = 0
        result.update(
            {
                "url": str(summary.get("url") or defaults["url"]),
                "title": str(summary.get("title") or ""),
                "html_length": html_length,
                "has_form": _as_bool(summary.get("has_form", False)),
                "has_login": _as_bool(summary.get("has_login", False)),
                "has_websocket": _as_bool(summary.get("has_websocket", False)),
            }
        )
        return result

    @staticmethod
    def _console_messages(result: Any) -> List[str]:
        if isinstance(result, Mapping):
            for key in (
                "logs",
                "messages",
                "console_logs",
                "console_messages",
            ):
                value = result.get(key)
                if isinstance(value, list):
                    return BrowserController._console_messages(value)
            for key in ("structuredContent", "data", "result", "value", "content"):
                nested = result.get(key)
                if nested is not None and nested is not result:
                    messages = BrowserController._console_messages(nested)
                    if messages:
                        return messages
            text = result.get("text") or result.get("message")
            return [str(text)] if text is not None else []
        if isinstance(result, list):
            messages: List[str] = []
            for item in result:
                if isinstance(item, str):
                    messages.extend(item.splitlines() or [item])
                elif isinstance(item, Mapping):
                    text = item.get("text") or item.get("message")
                    if text is not None:
                        messages.extend(str(text).splitlines() or [str(text)])
                    else:
                        messages.extend(BrowserController._console_messages(item))
            return messages
        if isinstance(result, str):
            return result.splitlines() or [result]
        return []

    @staticmethod
    def classify_hook_messages(messages: Iterable[str]) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        rejected = 0
        for message in messages:
            text = str(message)
            marker = text.find(HOOK_PREFIX)
            if marker < 0:
                continue
            try:
                parsed = json.loads(text[marker + len(HOOK_PREFIX):])
                if not isinstance(parsed, Mapping):
                    raise ValueError("hook record must be an object")
                records.append(dict(parsed))
            except (json.JSONDecodeError, TypeError, ValueError):
                rejected += 1

        network = [
            item for item in records if str(item.get("hook", "")).casefold() in {"xhr", "fetch"}
        ]
        crypto = [
            item for item in records if str(item.get("hook", "")).casefold() == "crypto"
        ]
        storage = [
            item
            for item in records
            if str(item.get("hook", "")).casefold() in {"storage", "cookie"}
        ]
        websocket = [
            item for item in records if str(item.get("hook", "")).casefold() == "websocket"
        ]
        return {
            "accepted": len(records),
            "rejected": rejected,
            "hook_results": records,
            "network_requests": network,
            "crypto_operations": crypto,
            "storage_operations": storage,
            "websocket_messages": websocket,
        }

    async def _execute_hook_results(
        self,
        plan: Dict[str, Any],
    ) -> Dict[str, Any]:
        assert self.execution_adapter is not None
        console_result = await self.execution_adapter.execute_call(
            "browser_console_logs",
            {},
        )
        console_error = _result_error(console_result)
        if console_error:
            error = console_error
            return {
                **plan,
                "status": _error_status(error),
                "execution": "failed",
                "execution_results": [
                    {"tool": "browser_console_logs", "result": console_result}
                ],
                "error": error,
                **self.classify_hook_messages([]),
            }
        classified = self.classify_hook_messages(self._console_messages(console_result))
        return {
            **plan,
            "status": "ok",
            "execution": "completed",
            "execution_results": [
                {"tool": "browser_console_logs", "result": console_result}
            ],
            **classified,
        }

    async def _execute_hooks(
        self,
        plan: Dict[str, Any],
    ) -> Dict[str, Any]:
        assert self.execution_adapter is not None
        expected_url = str(plan.get("expected_url", ""))
        hook_statuses: List[Dict[str, Any]] = []
        execution_results: List[Dict[str, Any]] = []
        current_url = expected_url
        navigation_changed = False
        errors: List[str] = []

        for hook, call in zip(plan.get("hooks", []), plan.get("calls", [])):
            result = await self.execution_adapter.execute_call(
                str(call.get("tool", "")),
                call.get("arguments", {}),
            )
            execution_results.append({"tool": call.get("tool", ""), "result": result})
            payload = _structured_mapping(result)
            result_error = _result_error(result)
            if result_error:
                error = result_error
                errors.append(error)
                hook_statuses.append(
                    {"hook": hook, "status": _error_status(error), "error": error}
                )
                continue
            if payload.get("url"):
                current_url = str(payload["url"])
                if expected_url and _url_identity(current_url) != _url_identity(expected_url):
                    navigation_changed = True
            installed = payload.get("installed")
            hook_statuses.append(
                {
                    "hook": hook,
                    "status": (
                        "unconfirmed"
                        if installed is None
                        else "installed"
                        if _as_bool(installed)
                        else "not_installed"
                    ),
                }
            )

        status = "ok"
        if errors:
            status = "timeout" if all(_error_status(item) == "timeout" for item in errors) else "error"
        elif navigation_changed:
            status = "navigation_changed"
        return {
            **plan,
            "status": status,
            "execution": "failed" if errors else "completed",
            "execution_results": execution_results,
            "hook_statuses": hook_statuses,
            "expected_url": expected_url,
            "current_url": current_url,
            **({"error": "; ".join(errors)} if errors else {}),
        }

    def navigate_and_wait(
        self,
        target_url: str,
        wait_for: str | Mapping[str, Any] | None = None,
        execute: bool = False,
    ) -> Any:
        url = self._authorize("GET", target_url)
        waits: Dict[str, Any]
        if isinstance(wait_for, str):
            waits = {"selector": wait_for}
        else:
            waits = dict(wait_for or {})
        timeout_ms = max(1, min(int(waits.get("timeout_ms", 30000)), 120000))
        calls = [_call("browser_navigate", url=url)]

        selector_wait = waits.get("selector") or waits.get("waitForSelector")
        response_wait = waits.get("response_url") or waits.get("waitForResponse")
        navigation_wait = waits.get("navigation") or waits.get("waitForNavigation")
        network_idle_wait = waits.get("network_idle") or waits.get("waitForNetworkIdle")
        function_wait = waits.get("function") or waits.get("waitForFunction")

        if selector_wait:
            selector = str(selector_wait)
            calls.append(
                self._run_code(
                    "async (page) => page.waitForSelector("
                    f"{_json(selector)}, {{timeout: {timeout_ms}}})",
                    selector=selector,
                    timeout_ms=timeout_ms,
                )
            )
        if response_wait:
            pattern = str(response_wait)
            calls.append(
                self._run_code(
                    "async (page) => page.waitForResponse("
                    f"response => response.url().includes({_json(pattern.replace('**', ''))}), "
                    f"{{timeout: {timeout_ms}}})",
                    response_url=pattern,
                    timeout_ms=timeout_ms,
                )
            )
        if navigation_wait:
            calls.append(
                self._run_code(
                    "async (page) => page.waitForNavigation("
                    f"{{waitUntil: 'domcontentloaded', timeout: {timeout_ms}}})",
                    timeout_ms=timeout_ms,
                )
            )
        if network_idle_wait:
            calls.append(
                self._run_code(
                    "async (page) => page.waitForLoadState("
                    f"'networkidle', {{timeout: {timeout_ms}}})",
                    timeout_ms=timeout_ms,
                )
            )
        if function_wait:
            expression = str(function_wait)
            calls.append(
                self._run_code(
                    "async (page) => page.waitForFunction("
                    f"{_json(expression)}, undefined, {{timeout: {timeout_ms}}})",
                    function=expression,
                    timeout_ms=timeout_ms,
                )
            )
        calls.append(_call("browser_snapshot"))
        plan = self._plan(
            "navigate_and_wait",
            calls,
            target_url=url,
            wait_for=waits,
        )
        return self._maybe_execute(plan, execute, self._execute_navigation)

    def click_and_capture(
        self,
        selector: str | Mapping[str, Any],
        capture_network: bool = True,
        execute: bool = False,
    ) -> Any:
        target = dict(selector) if isinstance(selector, Mapping) else {"selector": str(selector)}
        calls = [
            _call("browser_snapshot"),
            _call("browser_click", target=target),
        ]
        if capture_network:
            calls.append(_call("browser_network_requests", include_static=False))
        plan = self._plan(
            "click_and_capture",
            calls,
            target=target,
            capture_network=bool(capture_network),
        )
        return self._maybe_execute(plan, execute)

    def fill_form_and_submit(
        self,
        form_fields: Mapping[str, Any],
        submit_button: str | Mapping[str, Any],
        execute: bool = False,
    ) -> Any:
        fields: List[Dict[str, Any]] = []
        for name, raw_spec in form_fields.items():
            spec = dict(raw_spec) if isinstance(raw_spec, Mapping) else {"value": raw_spec}
            fields.append(
                {
                    "name": str(name),
                    "value": spec.get("value", ""),
                    "type": str(spec.get("type", "text")).casefold(),
                    "selector": spec.get("selector"),
                }
            )
        submit = (
            dict(submit_button)
            if isinstance(submit_button, Mapping)
            else {"selector": str(submit_button)}
        )
        calls = [
            _call("browser_snapshot"),
            _call("browser_fill_form", fields=fields),
            _call("browser_click", target=submit),
        ]
        plan = self._plan(
            "fill_form_and_submit",
            calls,
            form_fields=fields,
            submit_button=submit,
        )
        return self._maybe_execute(plan, execute)

    def scroll_and_load_more(
        self,
        scroll_times: int = 1,
        execute: bool = False,
    ) -> Any:
        times = max(1, min(int(scroll_times), 100))
        code = (
            "async (page) => {\n"
            f"  const scrollTimes = {times};\n"
            "  for (let index = 0; index < scrollTimes; index += 1) {\n"
            "    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));\n"
            "    await page.waitForTimeout(500);\n"
            "  }\n"
            "  return {scrollTimes};\n"
            "}"
        )
        plan = self._plan(
            "scroll_and_load_more",
            [self._run_code(code, scroll_times=times)],
            scroll_times=times,
        )
        return self._maybe_execute(plan, execute)

    def intercept_websocket(
        self,
        url_pattern: str = "*",
        execute: bool = False,
    ) -> Any:
        pattern = str(url_pattern or "*")
        if urlparse(pattern).scheme.casefold() in {"ws", "wss"}:
            pattern = self._authorize_websocket(pattern)
        code = (
            "async (page) => {\n"
            f"  const pattern = {_json(pattern)};\n"
            "  const messages = [];\n"
            "  page.on('websocket', socket => {\n"
            "    if (pattern !== '*' && !socket.url().includes(pattern.replaceAll('*', ''))) return;\n"
            "    socket.on('framesent', event => messages.push({direction: 'sent', payload: event.payload}));\n"
            "    socket.on('framereceived', event => messages.push({direction: 'received', payload: event.payload}));\n"
            "  });\n"
            "  return {installed: true, pattern};\n"
            "}"
        )
        plan = self._plan(
            "intercept_websocket",
            [self._run_code(code, url_pattern=pattern)],
            url_pattern=pattern,
        )
        return self._maybe_execute(plan, execute)

    def capture_network_traffic(
        self,
        duration: float = 5.0,
        execute: bool = False,
    ) -> Any:
        duration_ms = max(0, min(int(float(duration) * 1000), 300000))
        calls = [
            _call("browser_wait_for", time=duration_ms / 1000),
            _call("browser_network_requests", include_static=True),
        ]
        plan = self._plan(
            "capture_network_traffic",
            calls,
            duration_ms=duration_ms,
        )
        return self._maybe_execute(plan, execute)

    def inject_hooks(
        self,
        hook_sources: Mapping[str, str],
        expected_url: str = "",
        execute: bool = False,
    ) -> Any:
        selected = [
            (str(hook).strip().casefold(), str(source))
            for hook, source in hook_sources.items()
        ]
        if not selected:
            raise ValueError("at least one hook is required")
        calls = []
        for hook, source in selected:
            function = (
                "() => {\n"
                f"{source}\n"
                "  return {\n"
                f"    installed: Boolean(window.__hunterHooks && window.__hunterHooks[{_json(hook)}]),\n"
                "    url: window.location.href\n"
                "  };\n"
                "}"
            )
            calls.append(_call("browser_evaluate", function=function))
        plan = self._plan(
            "inject_hooks",
            calls,
            hooks=[hook for hook, _ in selected],
            expected_url=str(expected_url or ""),
        )
        return self._maybe_execute(plan, execute, self._execute_hooks)

    def get_hook_results(self, execute: bool = False) -> Any:
        plan = self._plan(
            "get_hook_results",
            [_call("browser_console_logs")],
        )
        return self._maybe_execute(plan, execute, self._execute_hook_results)

    def execute_in_context(
        self,
        js_code: str,
        execute: bool = False,
    ) -> Any:
        source = str(js_code or "")
        if not source.strip():
            raise ValueError("js_code must not be empty")
        plan = self._plan(
            "execute_in_context",
            [_call("browser_evaluate", function=source)],
        )
        return self._maybe_execute(plan, execute)

    def auto_login(
        self,
        url: str,
        username: str,
        password: str,
        login_button_selector: str | Mapping[str, Any] | None = None,
        execute: bool = False,
    ) -> Any:
        target = self._authorize("GET", url)
        button = login_button_selector or {"role": "button", "text": "Login"}
        submit = dict(button) if isinstance(button, Mapping) else {"selector": str(button)}
        fields = [
            {"name": "username", "value": str(username), "type": "text"},
            {"name": "password", "value": str(password), "type": "password"},
        ]
        calls = [
            _call("browser_navigate", url=target),
            _call("browser_snapshot"),
            _call("browser_fill_form", fields=fields, auto_detect=True),
            _call("browser_click", target=submit),
            self._run_code(
                "async (page) => page.waitForLoadState('networkidle', {timeout: 30000})"
            ),
            _call("browser_snapshot"),
        ]
        plan = self._plan(
            "auto_login",
            calls,
            target_url=target,
            username_field="auto",
            password_field="auto",
            submit_button=submit,
        )
        return self._maybe_execute(plan, execute)

    def auto_navigate_spa(
        self,
        base_url: str,
        target_state: str,
        execute: bool = False,
    ) -> Any:
        target = self._authorize("GET", base_url)
        desired_state = str(target_state or "").strip()
        if not desired_state:
            raise ValueError("target_state must not be empty")
        code = (
            "async (page) => {\n"
            f"  const targetState = {_json(desired_state)};\n"
            "  const candidate = page.getByText(targetState, {exact: true}).first();\n"
            "  if (await candidate.count()) await candidate.click();\n"
            "  else await page.evaluate(state => history.pushState({}, '', state), targetState);\n"
            "  await page.waitForLoadState('networkidle');\n"
            "  return {targetState, url: page.url()};\n"
            "}"
        )
        plan = self._plan(
            "auto_navigate_spa",
            [
                _call("browser_navigate", url=target),
                _call("browser_snapshot"),
                self._run_code(code, target_state=desired_state),
                _call("browser_snapshot"),
            ],
            base_url=target,
            target_state=desired_state,
        )
        return self._maybe_execute(plan, execute)

    def auto_trigger_api(
        self,
        url: str,
        action_description: str,
        execute: bool = False,
    ) -> Any:
        target = self._authorize("GET", url)
        description = str(action_description or "").strip()
        if not description:
            raise ValueError("action_description must not be empty")
        code = (
            "async (page) => {\n"
            f"  const description = {_json(description)};\n"
            "  const candidate = page.getByText(description, {exact: false}).first();\n"
            "  if (!await candidate.count()) return {triggered: false, description};\n"
            "  await candidate.click();\n"
            "  return {triggered: true, description};\n"
            "}"
        )
        plan = self._plan(
            "auto_trigger_api",
            [
                _call("browser_navigate", url=target),
                _call("browser_snapshot"),
                self._run_code(code, action_description=description),
                _call("browser_network_requests", include_static=False),
            ],
            target_url=target,
            action_description=description,
        )
        return self._maybe_execute(plan, execute)

    def snapshot(
        self,
        include_network: bool = False,
        execute: bool = False,
    ) -> Any:
        calls = [_call("browser_snapshot")]
        if include_network:
            calls.append(_call("browser_network_requests", include_static=False))
        calls.append(_call("browser_console_messages", level="info"))
        plan = self._plan(
            "snapshot",
            calls,
            include_network=bool(include_network),
        )
        return self._maybe_execute(plan, execute)

    def route_observations(self, observations: Mapping[str, Any]) -> Dict[str, Any]:
        """Turn passive browser observations into confirmation-gated Hunter calls."""

        hunter_calls: List[Dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def append(tool: str, **arguments: Any) -> None:
            key = (tool, _json(arguments))
            if key in seen:
                return
            seen.add(key)
            hunter_calls.append(_hunter_call(tool, **arguments))

        for raw_url in observations.get("urls", []) or []:
            url = self._authorize("GET", str(raw_url))
            append("hunter_scan_plan", target=url, mode="fast")

        for endpoint in observations.get("api_endpoints", []) or []:
            if isinstance(endpoint, Mapping):
                method = str(endpoint.get("method", "GET")).upper()
                url = self._authorize(method, str(endpoint.get("url", "")))
            else:
                method = "GET"
                url = self._authorize(method, str(endpoint))
            append(
                "hunter_scan_plan",
                target=url,
                mode="fast",
            )

        for websocket in observations.get("websockets", []) or []:
            raw_url = websocket.get("url", "") if isinstance(websocket, Mapping) else websocket
            url = self._authorize_websocket(str(raw_url))
            append("hunter_auto_websocket", target=url)

        for form in observations.get("forms", []) or []:
            if not isinstance(form, Mapping):
                continue
            method = str(form.get("method", "GET")).upper()
            action = self._authorize(method, str(form.get("action", "")))
            fields = [str(field) for field in form.get("fields", [])]
            append("hunter_auto_csrf", target=action)
            for field in fields or ["q"]:
                append("hunter_auto_xss", target=action, param=field, method=method)
                append("hunter_auto_sqli", target=action, param=field, method=method)

        return {
            "status": "proposed",
            "execution": "deferred",
            "requires_confirmation": True,
            "hunter_calls": hunter_calls,
        }
