from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTED_SOURCES = [
    *sorted((ROOT / "core").glob("auto_*.py")),
    ROOT / "core" / "probe.py",
    ROOT / "core" / "inject.py",
    ROOT / "core" / "src_read.py",
]
HTTP_MODULES = {"requests", "httpx", "aiohttp"}
BROKER_ADAPTED_SOURCES = [
    ROOT / "core" / name
    for name in (
        "auto_sqli.py",
        "auto_xss.py",
        "auto_ssrf.py",
        "auto_ssti.py",
        "auto_cmd.py",
        "auto_cors.py",
        "auto_csrf.py",
        "auto_graphql.py",
        "auto_jwt.py",
        "auto_websocket.py",
        "auto_xxe.py",
        "auto_access_control.py",
        "inject.py",
        "src_read.py",
    )
]


class DirectHttpVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.aliases: set[str] = set()
        self.violations: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            if item.name.split(".", 1)[0] in HTTP_MODULES:
                self.aliases.add(item.asname or item.name.split(".", 1)[0])
                self.violations.append(f"{self.path.name}:{node.lineno}: import {item.name}")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if (node.module or "").split(".", 1)[0] in HTTP_MODULES:
            self.aliases.update(item.asname or item.name for item in node.names)
            self.violations.append(f"{self.path.name}:{node.lineno}: from {node.module} import")

    def visit_Call(self, node: ast.Call) -> None:
        target = node.func
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            if target.value.id in self.aliases:
                self.violations.append(
                    f"{self.path.name}:{node.lineno}: direct HTTP call {target.value.id}.{target.attr}"
                )
        self.generic_visit(node)


def test_legacy_scanners_have_no_direct_http_client_boundary_bypass():
    violations: list[str] = []
    for path in ADAPTED_SOURCES:
        visitor = DirectHttpVisitor(path)
        visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        violations.extend(visitor.violations)

    assert not violations, "\n".join(violations)


def test_named_legacy_scanners_depend_on_request_broker():
    missing = [
        path.name
        for path in BROKER_ADAPTED_SOURCES
        if "core.request_broker" not in path.read_text(encoding="utf-8")
    ]

    assert not missing, ", ".join(missing)
