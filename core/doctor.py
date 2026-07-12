"""Portable Integration v2 diagnostics for the Hunter MCP server."""
from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

CONTRACT_FILENAME = "integration-contract.json"


def _result(tool: str, status: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"tool": tool, "status": status, "data": data, "evidence": {}, "next_actions": []}


def load_integration_contract(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    data = json.loads(source.read_text(encoding="utf-8-sig"))
    required = {"contract_version", "server_name", "minimum_tool_count", "required_tools", "workspace_schema_version"}
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"Contract missing fields: {', '.join(missing)}")
    if data["server_name"] != "hunter_tools":
        raise ValueError("Contract server_name must be hunter_tools")
    if not isinstance(data["required_tools"], list) or not all(isinstance(x, str) for x in data["required_tools"]):
        raise ValueError("Contract required_tools must be a string list")
    if not isinstance(data["minimum_tool_count"], int) or data["minimum_tool_count"] < 1:
        raise ValueError("Contract minimum_tool_count must be a positive integer")
    return data


class HunterDoctor:
    def __init__(
        self,
        hunter_dir: str | Path,
        registered_tools: Iterable[str],
        contract_path: Optional[str | Path] = None,
        config_paths: Optional[Iterable[str | Path]] = None,
        workspace_root: Optional[str | Path] = None,
    ) -> None:
        self.hunter_dir = Path(hunter_dir).expanduser().resolve()
        self.registered_tools = sorted(set(registered_tools))
        self.contract_path = Path(contract_path or self.hunter_dir / CONTRACT_FILENAME).expanduser().resolve()
        self.workspace_root = Path(workspace_root).expanduser().resolve() if workspace_root else None
        self.config_paths = [Path(p).expanduser().resolve() for p in config_paths] if config_paths is not None else self.discover_config_paths()

    def discover_config_paths(self) -> list[Path]:
        candidates: list[Path] = []
        codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
        candidates.append(codex_home / "config.toml")
        if self.workspace_root:
            candidates.extend([self.workspace_root / ".codex" / "config.toml", self.workspace_root / ".mcp.json"])
        result: list[Path] = []
        for path in candidates:
            resolved = path.resolve()
            if resolved not in result:
                result.append(resolved)
        return result

    def contract_check(self) -> dict[str, Any]:
        try:
            contract = load_integration_contract(self.contract_path)
            missing = sorted(set(contract["required_tools"]) - set(self.registered_tools))
            count_ok = len(self.registered_tools) >= contract["minimum_tool_count"]
            data = {
                **contract,
                "path": str(self.contract_path),
                "registered_tool_count": len(self.registered_tools),
                "missing_tools": missing,
                "minimum_tool_count_satisfied": count_ok,
            }
            return _result("hunter_contract_check", "ok" if not missing and count_ok else "error", data)
        except Exception as exc:
            return _result("hunter_contract_check", "error", {"path": str(self.contract_path), "error": str(exc)})

    @staticmethod
    def _registrations(path: Path) -> tuple[set[str], Optional[str]]:
        try:
            if path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                return set(data.get("mcpServers", {})), None
            import tomllib
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
            return set(data.get("mcp_servers", {})), None
        except Exception as exc:
            return set(), str(exc)

    def config_audit(self) -> dict[str, Any]:
        inspected = []
        legacy = []
        missing_complete = []
        parse_errors = []
        for path in self.config_paths:
            item: dict[str, Any] = {"path": str(path), "exists": path.is_file()}
            if path.is_file():
                registrations, error = self._registrations(path)
                item["registrations"] = sorted(registrations)
                if error:
                    item["error"] = error
                    parse_errors.append(str(path))
                else:
                    if "hunter" in registrations:
                        legacy.append(str(path))
                    if "hunter_tools" not in registrations:
                        missing_complete.append(str(path))
            inspected.append(item)
        ok = not legacy and not parse_errors
        return _result("hunter_config_audit", "ok" if ok else "error", {
            "inspected": inspected,
            "legacy_registrations": legacy,
            "missing_hunter_tools": missing_complete,
            "parse_errors": parse_errors,
            "note": "Missing hunter_tools is informational for configs that do not manage Hunter; legacy hunter is an error.",
        })

    def runtime_status(self) -> dict[str, Any]:
        contract = None
        try:
            contract = load_integration_contract(self.contract_path)
        except Exception:
            pass
        return _result("hunter_runtime_status", "ok", {
            "server_name": (contract or {}).get("server_name", "hunter_tools"),
            "pid": os.getpid(),
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "cwd": str(Path.cwd().resolve()),
            "hunter_dir": str(self.hunter_dir),
            "workspace_root": str(self.workspace_root) if self.workspace_root else None,
            "registered_tool_count": len(self.registered_tools),
            "environment": {name: os.environ.get(name) for name in ("CODEX_HOME", "OPEN_TGTYLAB_ROOT", "OPEN_TGTYLAB_WORKSPACE", "TGTYLAB_ROOT") if os.environ.get(name)},
        })

    def run(self) -> dict[str, Any]:
        checks = {
            "contract": self.contract_check(),
            "config": self.config_audit(),
            "runtime": self.runtime_status(),
        }
        status = "ok" if all(item["status"] == "ok" for item in checks.values()) else "degraded"
        return _result("hunter_doctor", status, {"checks": checks})
