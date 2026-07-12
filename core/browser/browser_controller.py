"""Build deferred Playwright MCP plans without controlling a browser directly."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping
from urllib.parse import urlparse


PLAYWRIGHT_BACKEND = "playwright-mcp"
PLAYWRIGHT_MODE = "external-mcp-handoff"


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
    ) -> None:
        self.artifact_dir = Path(artifact_dir).resolve() if artifact_dir else None
        self.attack_session = attack_session

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

    def navigate_and_wait(
        self,
        target_url: str,
        wait_for: str | Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
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
        return self._plan("navigate_and_wait", calls, target_url=url, wait_for=waits)

    def click_and_capture(
        self,
        selector: str | Mapping[str, Any],
        capture_network: bool = True,
    ) -> Dict[str, Any]:
        target = dict(selector) if isinstance(selector, Mapping) else {"selector": str(selector)}
        calls = [
            _call("browser_snapshot"),
            _call("browser_click", target=target),
        ]
        if capture_network:
            calls.append(_call("browser_network_requests", include_static=False))
        return self._plan(
            "click_and_capture",
            calls,
            target=target,
            capture_network=bool(capture_network),
        )

    def fill_form_and_submit(
        self,
        form_fields: Mapping[str, Any],
        submit_button: str | Mapping[str, Any],
    ) -> Dict[str, Any]:
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
        return self._plan(
            "fill_form_and_submit",
            calls,
            form_fields=fields,
            submit_button=submit,
        )

    def scroll_and_load_more(self, scroll_times: int = 1) -> Dict[str, Any]:
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
        return self._plan(
            "scroll_and_load_more",
            [self._run_code(code, scroll_times=times)],
            scroll_times=times,
        )

    def intercept_websocket(self, url_pattern: str = "*") -> Dict[str, Any]:
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
        return self._plan(
            "intercept_websocket",
            [self._run_code(code, url_pattern=pattern)],
            url_pattern=pattern,
        )

    def capture_network_traffic(self, duration: float = 5.0) -> Dict[str, Any]:
        duration_ms = max(0, min(int(float(duration) * 1000), 300000))
        calls = [
            _call("browser_wait_for", time=duration_ms / 1000),
            _call("browser_network_requests", include_static=True),
        ]
        return self._plan(
            "capture_network_traffic",
            calls,
            duration_ms=duration_ms,
        )

    def execute_in_context(self, js_code: str) -> Dict[str, Any]:
        source = str(js_code or "")
        if not source.strip():
            raise ValueError("js_code must not be empty")
        return self._plan(
            "execute_in_context",
            [_call("browser_evaluate", function=source)],
        )

    def auto_login(
        self,
        url: str,
        username: str,
        password: str,
        login_button_selector: str | Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
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
        return self._plan(
            "auto_login",
            calls,
            target_url=target,
            username_field="auto",
            password_field="auto",
            submit_button=submit,
        )

    def auto_navigate_spa(self, base_url: str, target_state: str) -> Dict[str, Any]:
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
        return self._plan(
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

    def auto_trigger_api(self, url: str, action_description: str) -> Dict[str, Any]:
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
        return self._plan(
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

    def snapshot(self, include_network: bool = False) -> Dict[str, Any]:
        calls = [_call("browser_snapshot")]
        if include_network:
            calls.append(_call("browser_network_requests", include_static=False))
        calls.append(_call("browser_console_messages", level="info"))
        return self._plan(
            "snapshot",
            calls,
            include_network=bool(include_network),
        )

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
