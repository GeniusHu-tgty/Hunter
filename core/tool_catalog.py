"""Shared classification for Hunter core, extension, and unknown tools."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def classify_tool_inventory(
    core_tools: Iterable[str],
    extension_tools: Mapping[str, Iterable[str]] | None = None,
    unknown_tools: Iterable[str] | None = None,
    optional_extension_namespaces: Iterable[str] = (),
    declared_collisions: Iterable[Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return globally unique, mutually exclusive tool categories."""
    core = {str(name) for name in core_tools}
    namespaces = tuple(optional_extension_namespaces)
    claims: dict[str, set[str]] = {}
    for raw_source, names in (extension_tools or {}).items():
        source = str(raw_source)
        for name in {str(item) for item in names} - core:
            claims.setdefault(name, set()).add(source)

    extension_sets: dict[str, set[str]] = {}
    invalid_extensions: set[str] = set()
    collision_sources: dict[str, set[str]] = {}

    for name, sources in claims.items():
        if len(sources) > 1:
            collision_sources.setdefault(name, set()).update(sources)
        if namespaces and name.startswith(namespaces):
            source = (
                "contract_extensions"
                if len(sources) > 1
                else next(iter(sources))
            )
            extension_sets.setdefault(source, set()).add(name)
        else:
            invalid_extensions.add(name)

    assigned_extensions = {
        name
        for names in extension_sets.values()
        for name in names
    }
    extensions = {
        source: sorted(names)
        for source, names in sorted(extension_sets.items())
        if names
    }

    unknown = (
        {str(name) for name in (unknown_tools or ())}
        | invalid_extensions
    ) - core - assigned_extensions
    counts = {
        "core": len(core),
        "extensions": len(assigned_extensions),
        "unknown": len(unknown),
    }
    counts["total"] = (
        counts["core"]
        + counts["extensions"]
        + counts["unknown"]
    )
    for collision in declared_collisions or ():
        tool = str(collision.get("tool", ""))
        if not tool:
            continue
        sources = collision_sources.setdefault(tool, set())
        for key in ("sources", "existing_sources"):
            values = collision.get(key, ())
            if isinstance(values, str):
                values = [values]
            sources.update(
                str(source)
                for source in values
                if str(source)
            )
        for key in ("existing_source", "incoming_source"):
            value = collision.get(key)
            if value:
                sources.add(str(value))

    collisions = [
        {
            "tool": tool,
            "sources": sorted(sources),
        }
        for tool, sources in sorted(collision_sources.items())
        if len(sources) > 1
    ]
    return (
        {
            "core": sorted(core),
            "extensions": extensions,
            "unknown": sorted(unknown),
            "counts": counts,
            "collisions": collisions,
            "collision_count": len(collisions),
        },
        sorted(invalid_extensions - core),
    )
