"""Portable Integration v2 diagnostics for the Hunter MCP server."""
from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

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
    exact_core_tool_count = data.get(
        "exact_core_tool_count",
        data["minimum_tool_count"],
    )
    if (
        not isinstance(exact_core_tool_count, int)
        or exact_core_tool_count < 1
    ):
        raise ValueError(
            "Contract exact_core_tool_count must be a positive integer"
        )
    optional_namespaces = data.get(
        "optional_extension_namespaces",
        [],
    )
    if (
        not isinstance(optional_namespaces, list)
        or not all(
            isinstance(namespace, str) and namespace
            for namespace in optional_namespaces
        )
    ):
        raise ValueError(
            "Contract optional_extension_namespaces must be a string list"
        )
    unknown_tool_policy = data.get("unknown_tool_policy", "error")
    if unknown_tool_policy not in {"error", "warning"}:
        raise ValueError(
            "Contract unknown_tool_policy must be error or warning"
        )
    data["exact_core_tool_count"] = exact_core_tool_count
    data["optional_extension_namespaces"] = optional_namespaces
    data["unknown_tool_policy"] = unknown_tool_policy
    return data


class HunterDoctor:
    def __init__(
        self,
        hunter_dir: str | Path,
        registered_tools: Iterable[str],
        contract_path: Optional[str | Path] = None,
        config_paths: Optional[Iterable[str | Path]] = None,
        workspace_root: Optional[str | Path] = None,
        extension_tools: Optional[
            Mapping[str, Iterable[str]]
        ] = None,
        unknown_tools: Optional[Iterable[str]] = None,
    ) -> None:
        self.hunter_dir = Path(hunter_dir).expanduser().resolve()
        self.registered_tools = sorted(set(registered_tools))
        self.extension_tools = {
            source: sorted(set(names))
            for source, names in (extension_tools or {}).items()
        }
        self.unknown_tools = sorted(set(unknown_tools or []))
        self.contract_path = Path(contract_path or self.hunter_dir / CONTRACT_FILENAME).expanduser().resolve()
        self.workspace_root = Path(workspace_root).expanduser().resolve() if workspace_root else None
        self.config_paths = [Path(p).expanduser().resolve() for p in config_paths] if config_paths is not None else self.discover_config_paths()

    def _tool_counts(self) -> dict[str, int]:
        extension_count = sum(
            len(names) for names in self.extension_tools.values()
        )
        return {
            "core": len(self.registered_tools),
            "extensions": extension_count,
            "unknown": len(self.unknown_tools),
            "total": (
                len(self.registered_tools)
                + extension_count
                + len(self.unknown_tools)
            ),
        }

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
            required_core = set(contract["required_tools"])
            registered_core = set(self.registered_tools)
            missing = sorted(required_core - registered_core)
            unexpected = sorted(registered_core - required_core)
            minimum_count_ok = (
                len(registered_core) >= contract["minimum_tool_count"]
            )
            exact_count_ok = (
                len(registered_core)
                == contract["exact_core_tool_count"]
            )
            declared_namespaces = tuple(
                contract["optional_extension_namespaces"]
            )
            invalid_extensions = sorted(
                name
                for names in self.extension_tools.values()
                for name in names
                if not declared_namespaces
                or not name.startswith(declared_namespaces)
            )
            unknown_tools = sorted(
                set(self.unknown_tools) | set(invalid_extensions)
            )
            unknown_is_error = (
                bool(unknown_tools)
                and contract["unknown_tool_policy"] == "error"
            )
            tool_counts = self._tool_counts()
            data = {
                **contract,
                "path": str(self.contract_path),
                "registered_tool_count": tool_counts["total"],
                "registered_core_tool_count": tool_counts["core"],
                "extension_tool_count": tool_counts["extensions"],
                "unknown_tool_count": len(unknown_tools),
                "missing_tools": missing,
                "missing_core_tools": missing,
                "unexpected_core_tools": unexpected,
                "extension_tools": self.extension_tools,
                "invalid_extension_tools": invalid_extensions,
                "unknown_tools": unknown_tools,
                "minimum_tool_count_satisfied": minimum_count_ok,
                "exact_core_tool_count_satisfied": exact_count_ok,
                "warnings": (
                    [f"Unknown registered tools: {', '.join(unknown_tools)}"]
                    if unknown_tools
                    and contract["unknown_tool_policy"] == "warning"
                    else []
                ),
            }
            valid = (
                not missing
                and not unexpected
                and minimum_count_ok
                and exact_count_ok
                and not unknown_is_error
            )
            return _result(
                "hunter_contract_check",
                "ok" if valid else "error",
                data,
            )
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
        tool_counts = self._tool_counts()
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
            "registered_tool_count": tool_counts["total"],
            "core_tool_count": tool_counts["core"],
            "extension_tool_count": tool_counts["extensions"],
            "extension_tool_counts": {
                source: len(names)
                for source, names in self.extension_tools.items()
            },
            "unknown_tool_count": tool_counts["unknown"],
            "unknown_tools": self.unknown_tools,
            "environment": {name: os.environ.get(name) for name in ("CODEX_HOME", "OPEN_TGTYLAB_ROOT", "OPEN_TGTYLAB_WORKSPACE", "TGTYLAB_ROOT") if os.environ.get(name)},
        })

    def run(self) -> dict[str, Any]:
        checks = {
            "contract": self.contract_check(),
            "config": self.config_audit(),
            "runtime": self.runtime_status(),
        }
        status = "ok" if all(item["status"] == "ok" for item in checks.values()) else "degraded"
        return _result(
            "hunter_doctor",
            status,
            {
                "tool_counts": self._tool_counts(),
                "checks": checks,
            },
        )
