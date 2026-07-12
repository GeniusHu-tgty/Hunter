"""Conservative JavaScript bundle detection and module extraction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_BUNDLER_SIGNALS = {
    "webpack": (
        (r"\b__webpack_require__\b", "__webpack_require__", 0.45),
        (r"\b__webpack_modules__\b", "__webpack_modules__", 0.4),
        (r"\bwebpackChunk\w*\b", "webpackChunk", 0.35),
    ),
    "webpack5": (
        (r"\b__webpack_require__\.[A-Za-z]\b", "webpack runtime helpers", 0.35),
        (r"\bwebpackChunk\w*\b", "webpackChunk", 0.45),
        (r"\b__webpack_modules__\b", "__webpack_modules__", 0.3),
    ),
    "vite": (
        (r"\b__vite__mapDeps\b", "__vite__mapDeps", 0.6),
        (r"\b__vite__injectQuery\b", "__vite__injectQuery", 0.6),
    ),
    "rollup": (
        (r"/\*!\s*Rollup\s*\*/", "Rollup banner", 0.8),
        (r"\bObject\.defineProperty\(exports,\s*['\"]__esModule", "CommonJS export wrapper", 0.35),
    ),
    "parcel": (
        (r"\bparcelRequire\b", "parcelRequire", 0.8),
        (r"\bnewRequire\b.*\bmodules\b", "Parcel runtime", 0.4),
    ),
    "esbuild": (
        (r"\b__commonJS\b", "__commonJS", 0.5),
        (r"\b__toESM\b", "__toESM", 0.35),
        (r"\b__export\b", "__export", 0.25),
    ),
    "turbopack": (
        (r"\b__turbopack_context__\b", "__turbopack_context__", 0.7),
        (r"\bTURBOPACK\b", "TURBOPACK", 0.5),
    ),
}


def detect_bundler(source: str) -> dict[str, Any]:
    """Return the most likely bundler using explicit runtime fingerprints."""
    candidates = []
    for bundler, patterns in _BUNDLER_SIGNALS.items():
        score = 0.0
        signals = []
        for pattern, label, weight in patterns:
            if re.search(pattern, source, re.DOTALL):
                score += weight
                signals.append(label)
        candidates.append({"bundler": bundler, "confidence": min(score, 1.0), "signals": signals})
    candidates.sort(key=lambda item: item["confidence"], reverse=True)
    best = candidates[0]
    if best["confidence"] == 0:
        best = {"bundler": "unknown", "confidence": 0.0, "signals": []}
    elif best["bundler"] == "webpack5" and "__webpack_require__" in source and "__webpack_modules__" in source:
        best = next(item for item in candidates if item["bundler"] == "webpack")
    return {**best, "candidates": candidates}


def unpack_bundle(source: str, output_dir: str | Path | None = None, source_name: str = "bundle.js") -> dict[str, Any]:
    """Extract statically recognizable modules and optionally write artifacts."""
    detection = detect_bundler(source)
    bundler = detection["bundler"]
    if bundler in {"webpack", "webpack5"}:
        modules = _extract_webpack_modules(source)
    else:
        modules = _extract_esm_modules(source, source_name)
    tree = {
        "source": source_name,
        "bundler": bundler,
        "confidence": detection["confidence"],
        "signals": detection["signals"],
        "modules": [{key: value for key, value in module.items() if key != "code"} for module in modules],
        "edges": [
            {"from": module["id"], "to": dependency}
            for module in modules
            for dependency in module["dependencies"]
        ],
    }
    files = []
    if output_dir is not None:
        root = Path(output_dir)
        module_dir = root / "modules"
        module_dir.mkdir(parents=True, exist_ok=True)
        for module in modules:
            safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", module["id"])
            path = module_dir / f"{safe_id}.js"
            path.write_text(module["code"], encoding="utf-8")
            files.append(str(path))
        tree_path = root / "module_tree.json"
        tree_path.write_text(json.dumps(tree, indent=2, ensure_ascii=False), encoding="utf-8")
        files.append(str(tree_path))
    tree["files"] = files
    return tree


def _extract_webpack_modules(source: str) -> list[dict[str, Any]]:
    marker = re.search(r"\b__webpack_modules__\s*=\s*\(?\s*\{", source)
    if not marker:
        marker = re.search(r"\bwebpackChunk\w*\.push\s*\(\s*\[[\s\S]*?,\s*\{", source)
    if not marker:
        return []
    object_start = source.find("{", marker.start())
    object_end = _matching_delimiter(source, object_start, "{", "}")
    if object_end is None:
        return []
    body = source[object_start + 1 : object_end]
    entry_pattern = re.compile(r"(?:^|,)\s*(?:['\"]([^'\"]+)['\"]|([\w.-]+))\s*:\s*")
    entries = _top_level_entries(body, entry_pattern)
    modules = []
    for index, match in enumerate(entries):
        module_id = match.group(1) or match.group(2)
        code_end = entries[index + 1].start() if index + 1 < len(entries) else len(body)
        code = body[match.end():code_end].strip().rstrip(",").strip()
        modules.append(_module_record(str(module_id), code, f"modules/{module_id}.js"))
    return modules


def _top_level_entries(text: str, pattern: re.Pattern[str]) -> list[re.Match[str]]:
    entries = []
    depth = {"(": 0, "[": 0, "{": 0}
    quote = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char in depth:
            depth[char] += 1
        elif char in ")]}":
            opener = {")": "(", "]": "[", "}": "{"}[char]
            depth[opener] = max(0, depth[opener] - 1)
        elif (index == 0 or char == ",") and not any(depth.values()):
            match = pattern.match(text, index)
            if match:
                entries.append(match)
    if not entries:
        first = pattern.match(text, 0)
        if first:
            entries.append(first)
    return entries

def _find_next_top_level_entry(text: str, start: int, pattern: re.Pattern[str]):
    depth = {"(": 0, "[": 0, "{": 0}
    quote = None
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char in depth:
            depth[char] += 1
        elif char in ")]}":
            opener = {")": "(", "]": "[", "}": "{"}[char]
            depth[opener] = max(0, depth[opener] - 1)
        elif char == "," and not any(depth.values()):
            match = pattern.match(text, index)
            if match:
                return match
        index += 1
    return None


def _module_record(module_id: str, code: str, path: str) -> dict[str, Any]:
    dependencies = sorted(set(re.findall(r"\b__webpack_require__\s*\(\s*['\"]?([\w./-]+)", code)))
    dependencies.extend(dep for dep in re.findall(r"\brequire\s*\(\s*['\"]([^'\"]+)", code) if dep not in dependencies)
    exports = []
    if re.search(r"\bmodule\.exports\s*=", code):
        exports.append("default")
    exports.extend(name for name in re.findall(r"\bexports\.([A-Za-z_$][\w$]*)\s*=", code) if name not in exports)
    return {"id": module_id, "path": path, "dependencies": dependencies, "exports": exports, "size": len(code.encode("utf-8")), "code": code}


def _extract_esm_modules(source: str, source_name: str) -> list[dict[str, Any]]:
    dependencies = re.findall(r"\b(?:import[\s\S]*?from\s*|import\s*\(|require\s*\()['\"]([^'\"]+)", source)
    exports = re.findall(r"\bexport\s+(?:default\s+)?(?:const|let|var|function|class)?\s*([A-Za-z_$][\w$]*)?", source)
    exports = [name or "default" for name in exports]
    return [{"id": "0", "path": source_name, "dependencies": sorted(set(dependencies)), "exports": exports, "size": len(source.encode("utf-8")), "code": source}]


def _matching_delimiter(text: str, start: int, opener: str, closer: str) -> int | None:
    depth = 0
    quote = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
    return None

