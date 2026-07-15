"""Portable Integration v2 diagnostics for the Hunter MCP server."""
from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from core.tool_catalog import classify_tool_inventory

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
    if "exact_core_tool_count" in data:
        exact_core_tool_count = data["exact_core_tool_count"]
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
        invalid_extension_tools: Optional[Iterable[str]] = None,
        extension_collisions: Optional[
            Iterable[Mapping[str, Any]]
        ] = None,
    ) -> None:
        self.hunter_dir = Path(hunter_dir).expanduser().resolve()
        self.registered_tools = sorted(set(registered_tools))
        self.extension_tools = {
            source: sorted(set(names))
            for source, names in (extension_tools or {}).items()
        }
        self.unknown_tools = sorted(set(unknown_tools or []))
        self.invalid_extension_tools = sorted(
            set(invalid_extension_tools or [])
        )
        self.extension_collisions = [
            dict(collision)
            for collision in (extension_collisions or [])
        ]
        self.contract_path = Path(contract_path or self.hunter_dir / CONTRACT_FILENAME).expanduser().resolve()
        self.workspace_root = Path(workspace_root).expanduser().resolve() if workspace_root else None
        self.config_paths = [Path(p).expanduser().resolve() for p in config_paths] if config_paths is not None else self.discover_config_paths()

    def _inventory(
        self,
        contract: Optional[Mapping[str, Any]] = None,
    ) -> tuple[dict[str, Any], list[str]]:
        if contract is None:
            try:
                contract = load_integration_contract(self.contract_path)
            except Exception:
                contract = {}
        inventory, classified_invalid = classify_tool_inventory(
            self.registered_tools,
            self.extension_tools,
            self.unknown_tools,
            contract.get("optional_extension_namespaces", []),
            self.extension_collisions,
        )
        invalid_extensions = sorted(
            set(classified_invalid)
            | set(self.invalid_extension_tools)
        )
        assigned_tools = set(inventory["core"])
        assigned_tools.update(
            name
            for names in inventory["extensions"].values()
            for name in names
        )
        inventory["unknown"] = sorted(
            set(inventory["unknown"])
            | (set(invalid_extensions) - assigned_tools)
        )
        inventory["counts"]["unknown"] = len(inventory["unknown"])
        inventory["counts"]["total"] = (
            inventory["counts"]["core"]
            + inventory["counts"]["extensions"]
            + inventory["counts"]["unknown"]
        )
        inventory["invalid_extension_tools"] = invalid_extensions
        return inventory, invalid_extensions

    def _tool_counts(self) -> dict[str, int]:
        inventory, _ = self._inventory()
        return dict(inventory["counts"])

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
            inventory, invalid_extensions = self._inventory(contract)
            registered_core = set(inventory["core"])
            missing = sorted(required_core - registered_core)
            unexpected = sorted(registered_core - required_core)
            minimum_count_ok = (
                len(registered_core) >= contract["minimum_tool_count"]
            )
            exact_core_tool_count = contract.get(
                "exact_core_tool_count"
            )
            exact_count_ok = (
                len(registered_core) == exact_core_tool_count
                if exact_core_tool_count is not None
                else None
            )
            unknown_tools = inventory["unknown"]
            collisions = inventory["collisions"]
            unknown_is_error = (
                bool(unknown_tools)
                and contract["unknown_tool_policy"] == "error"
            )
            tool_counts = inventory["counts"]
            collision_errors = (
                [
                    "Extension tool source collisions: "
                    + "; ".join(
                        (
                            f"{collision['tool']} "
                            f"({', '.join(collision['sources'])})"
                        )
                        for collision in collisions
                    )
                ]
                if collisions
                else []
            )
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
                "extension_tools": inventory["extensions"],
                "invalid_extension_tools": invalid_extensions,
                "unknown_tools": unknown_tools,
                "collisions": collisions,
                "collision_count": len(collisions),
                "minimum_tool_count_satisfied": minimum_count_ok,
                "exact_core_tool_count_satisfied": exact_count_ok,
                "tool_counts": tool_counts,
                "errors": collision_errors,
                "warnings": (
                    [f"Unknown registered tools: {', '.join(unknown_tools)}"]
                    if unknown_tools
                    and contract["unknown_tool_policy"] == "warning"
                    else []
                ),
            }
            valid = (
                not missing
                and minimum_count_ok
                and (
                    exact_core_tool_count is None
                    or (not unexpected and exact_count_ok)
                )
                and not unknown_is_error
                and not collisions
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
        inventory, invalid_extensions = self._inventory(contract)
        tool_counts = inventory["counts"]
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
                for source, names in inventory["extensions"].items()
            },
            "unknown_tool_count": tool_counts["unknown"],
            "unknown_tools": inventory["unknown"],
            "invalid_extension_tools": invalid_extensions,
            "collisions": inventory["collisions"],
            "collision_count": len(inventory["collisions"]),
            "tool_counts": tool_counts,
            "environment": {name: os.environ.get(name) for name in ("CODEX_HOME", "OPEN_TGTYLAB_ROOT", "OPEN_TGTYLAB_WORKSPACE", "TGTYLAB_ROOT") if os.environ.get(name)},
        })

    def run(self) -> dict[str, Any]:
        inventory, invalid_extensions = self._inventory()
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
                "tool_counts": inventory["counts"],
                "invalid_extension_tools": invalid_extensions,
                "collisions": inventory["collisions"],
                "collision_count": len(inventory["collisions"]),
                "checks": checks,
            },
        )
