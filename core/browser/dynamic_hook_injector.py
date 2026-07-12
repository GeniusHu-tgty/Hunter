"""Build deferred Playwright MCP plans for browser hook injection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


HOOK_NAMES = ("xhr", "fetch", "crypto", "storage", "cookie", "websocket")


def _call(tool: str, **arguments: Any) -> Dict[str, Any]:
    return {"tool": tool, "arguments": arguments}


class DynamicHookInjector:
    """Load auditable JavaScript templates and build external MCP handoffs."""

    def __init__(self, template_dir: str | Path | None = None) -> None:
        self.template_dir = Path(template_dir or Path(__file__).with_name("hooks"))

    def template_path(self, hook: str) -> Path:
        normalized = str(hook).strip().lower()
        if normalized not in HOOK_NAMES:
            raise ValueError(f"unsupported hook: {hook}")
        return self.template_dir / f"{normalized}_hook.js"

    def read_template(self, hook: str) -> str:
        path = self.template_path(hook)
        source = path.read_text(encoding="utf-8")
        if len(source.encode("utf-8")) > 256 * 1024:
            raise ValueError(f"hook template is too large: {path.name}")
        return source

    def validate_templates(self) -> Dict[str, Dict[str, Any]]:
        validation: Dict[str, Dict[str, Any]] = {}
        for hook in HOOK_NAMES:
            path = self.template_path(hook)
            try:
                source = self.read_template(hook)
                valid = (
                    "__HUNTER_HOOK__" in source
                    and "__hunterHooks" in source
                    and source.count("{") == source.count("}")
                    and source.count("(") == source.count(")")
                )
                error = "" if valid else "required marker or balanced delimiter missing"
            except Exception as exc:
                valid = False
                error = str(exc)
            validation[hook] = {
                "path": str(path),
                "valid": valid,
                "error": error,
            }
        return validation

    def build_plan(
        self,
        hooks: Iterable[str],
        strategy: str = "preload",
        refresh_interval_ms: int = 5000,
    ) -> Dict[str, Any]:
        selected = list(dict.fromkeys(str(item).strip().lower() for item in hooks))
        if not selected:
            raise ValueError("at least one hook is required")
        sources = [self.read_template(hook) for hook in selected]
        strategy = strategy.strip().lower()

        if strategy == "preload":
            code = (
                "async (page) => {\n"
                f"  const sources = {json.dumps(sources)};\n"
                "  for (const content of sources) await page.addInitScript({content});\n"
                "  return {installed: sources.length, strategy: 'preload'};\n"
                "}"
            )
            calls = [_call("browser_run_code", code=code)]
        elif strategy == "postload":
            bundled = "\n".join(sources)
            calls = [_call("browser_evaluate", function=f"() => {{\n{bundled}\n}}")]
        elif strategy == "refresh":
            interval = max(1000, min(int(refresh_interval_ms), 60000))
            code = (
                "async (page) => {\n"
                f"  const sources = {json.dumps(sources)};\n"
                f"  const interval = {interval};\n"
                "  await page.evaluate(({sources, interval}) => {\n"
                "    const install = () => sources.forEach((source) => (0, eval)(source));\n"
                "    install();\n"
                "    if (!window.__hunterHookRefresh) {\n"
                "      window.__hunterHookRefresh = setInterval(install, interval);\n"
                "    }\n"
                "  }, {sources, interval});\n"
                "  return {installed: sources.length, strategy: 'refresh', interval};\n"
                "}"
            )
            calls = [_call("browser_run_code", code=code)]
        else:
            raise ValueError("strategy must be preload, postload, or refresh")

        return {
            "backend": "playwright-mcp",
            "mode": "external-mcp-handoff",
            "status": "proposed",
            "execution": "deferred",
            "requires_confirmation": False,
            "operation": "inject_hooks",
            "strategy": strategy,
            "hooks": selected,
            "calls": calls,
            "on_failure": [
                _call("browser_take_screenshot", filename="hunter-hook-failure.png"),
                _call("browser_snapshot"),
                _call("browser_console_messages", level="error"),
            ],
        }
