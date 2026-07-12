"""Conservative JavaScript bundle detection and logical module extraction."""

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
        (r"\bimport\.meta\.env\b", "import.meta.env", 0.25),
        (r"\bimport\s+(?:[\s\S]*?\s+from\s+)?['\"]", "ES module imports", 0.2),
    ),
    "rollup": (
        (r"/\*!\s*Rollup\s*\*/", "Rollup banner", 0.8),
        (r"\bObject\.defineProperty\(exports,\s*['\"]__esModule", "CommonJS export wrapper", 0.35),
        (r"\bexport\s+(?:default\s+)?(?:const|let|var|function|class)\b", "ES module exports", 0.25),
    ),
    "parcel": ((r"\bparcelRequire\b", "parcelRequire", 0.8),),
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
    candidates = []
    for bundler, patterns in _BUNDLER_SIGNALS.items():
        score = 0.0
        signals = []
        for pattern, label, weight in patterns:
            if re.search(pattern, source, re.DOTALL):
                score += weight
                signals.append(label)
        candidates.append({"bundler": bundler, "confidence": min(score, 1.0), "signals": signals})
    if re.search(r"\bimport\s+(?:[\s\S]*?\s+from\s+)?['\"]", source) and not re.search(r"/\*!\s*Rollup\s*\*/", source):
        vite = next(item for item in candidates if item["bundler"] == "vite")
        vite["confidence"] = max(vite["confidence"], 0.5)
    candidates.sort(key=lambda item: item["confidence"], reverse=True)
    best = candidates[0]
    if best["confidence"] == 0:
        best = {"bundler": "unknown", "confidence": 0.0, "signals": []}
    elif best["bundler"] == "webpack5" and "__webpack_require__" in source and "__webpack_modules__" in source:
        best = next(item for item in candidates if item["bundler"] == "webpack")
    return {**best, "candidates": candidates}


def unpack_bundle(source: str, output_dir: str | Path | None = None, source_name: str = "bundle.js") -> dict[str, Any]:
    detection = detect_bundler(source)
    bundler = detection["bundler"]
    modules = _extract_webpack_modules(source) if bundler in {"webpack", "webpack5"} else _extract_esm_modules(source, source_name)
    tree = {
        "source": source_name,
        "bundler": bundler,
        "confidence": detection["confidence"],
        "signals": detection["signals"],
        "logical_modules": bundler in {"vite", "rollup"},
        "vite_dependencies": _extract_vite_dependencies(source) if bundler == "vite" else [],
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


def _extract_vite_dependencies(source: str) -> list[str]:
    match = re.search(r"\bm\.f\s*\|\|\s*\(\s*m\.f\s*=\s*\[([\s\S]*?)\]\s*\)", source)
    if not match:
        return []
    return re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))


def _extract_webpack_modules(source: str) -> list[dict[str, Any]]:
    marker = re.search(r"\b__webpack_modules__\s*=\s*\(?\s*([\[{])", source)
    if not marker:
        marker = re.search(r"\bwebpackChunk\w*\.push\s*\(\s*\[[\s\S]*?,\s*([\[{])", source)
    if not marker:
        return []
    opener = marker.group(1)
    object_start = marker.start(1)
    object_end = _matching_delimiter(source, object_start, opener, "]" if opener == "[" else "}")
    if object_end is None:
        return []
    body = source[object_start + 1 : object_end]
    modules = []
    if opener == "{":
        entry_pattern = re.compile(r"(?:^|,)\s*(?:['\"]([^'\"]+)['\"]|([\w.-]+))\s*:\s*")
        entries = _top_level_entries(body, entry_pattern)
        for index, match in enumerate(entries):
            module_id = match.group(1) or match.group(2)
            code_end = entries[index + 1].start() if index + 1 < len(entries) else len(body)
            code = body[match.end():code_end].strip().rstrip(",").strip()
            modules.append(_module_record(str(module_id), code, f"modules/{module_id}.js"))
    else:
        entries = _split_top_level(body)
        for index, code in enumerate(entries):
            code = code.strip().rstrip(",").strip()
            if code:
                modules.append(_module_record(str(index), code, f"modules/{index}.js"))
    return modules


def _top_level_entries(text: str, pattern: re.Pattern[str]) -> list[re.Match[str]]:
    matches = []
    depth = {"{": 0, "[": 0, "(": 0}
    quote = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"`":
            quote = char
        elif char in depth:
            depth[char] += 1
        elif char in "}])":
            opener = {"}": "{", "]": "[", ")": "("}[char]
            depth[opener] = max(0, depth[opener] - 1)
        elif char == "," and not any(depth.values()):
            match = pattern.match(text, index)
            if match:
                matches.append(match)
        elif index == 0:
            match = pattern.match(text, index)
            if match:
                matches.append(match)
        index += 1
    return matches


def _split_top_level(text: str) -> list[str]:
    parts, start = [], 0
    depth = {"{": 0, "[": 0, "(": 0}
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
        elif char in "}])":
            opener = {"}": "{", "]": "[", ")": "("}[char]
            depth[opener] = max(0, depth[opener] - 1)
        elif char == "," and not any(depth.values()):
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _module_record(module_id: str, code: str, path: str) -> dict[str, Any]:
    dependencies = sorted(set(re.findall(r"\b__webpack_require__\s*\(\s*['\"]?([\w./-]+)", code)))
    dependencies.extend(dep for dep in re.findall(r"\brequire\s*\(\s*['\"]([^'\"]+)", code) if dep not in dependencies)
    exports = []
    if re.search(r"\bmodule\.exports\s*=", code):
        exports.append("default")
    exports.extend(name for name in re.findall(r"\bexports\.([A-Za-z_$][\w$]*)\s*=", code) if name not in exports)
    if re.search(r"__webpack_require__\.d\s*\(", code):
        exports.append("named")
    return {"id": module_id, "path": path, "dependencies": dependencies, "exports": exports, "size": len(code.encode("utf-8")), "code": code}


def _extract_esm_modules(source: str, source_name: str) -> list[dict[str, Any]]:
    imports = []
    for match in re.finditer(r"\bimport\s+(?:[\s\S]*?\s+from\s+)?(['\"])([^'\"]+)\1", source):
        if match.group(2) not in imports:
            imports.append(match.group(2))
    modules = []
    for index, dependency in enumerate(imports):
        modules.append({"id": f"import-{index}", "path": dependency, "dependencies": [], "exports": [], "size": 0, "code": match_import(source, dependency)})
    boundaries = [match.start() for match in re.finditer(r"(?m)^\s*(?=export\b)", source)]
    if not boundaries:
        boundaries = [0]
    elif boundaries[0] > 0:
        boundaries.insert(0, 0)
    for index, start in enumerate(sorted(set(boundaries))):
        end = boundaries[index + 1] if index + 1 < len(boundaries) else len(source)
        code = source[start:end].strip()
        if not code:
            continue
        dependencies = sorted(set(re.findall(r"\b(?:import\s+[\s\S]*?\s+from\s*|import\s*\(|require\s*\()['\"]([^'\"]+)", code)))
        exports = [name or "default" for name in re.findall(r"\bexport\s+(?:default\s+)?(?:const|let|var|function|class)?\s*([A-Za-z_$][\w$]*)?", code)]
        module = {"id": str(index), "path": f"{source_name}#module-{index}", "dependencies": dependencies, "exports": exports, "size": len(code.encode("utf-8")), "code": code}
        for dependency in imports:
            if dependency not in module["dependencies"]:
                module["dependencies"].append(dependency)
        modules.append(module)
    return modules or [{"id": "0", "path": source_name, "dependencies": imports, "exports": [], "size": len(source.encode("utf-8")), "code": source}]


def match_import(source: str, dependency: str) -> str:
    match = re.search(rf"(?m)^.*\bimport\b.*['\"]{re.escape(dependency)}['\"].*$", source)
    return match.group(0).strip() if match else f"import {dependency!r};"


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
