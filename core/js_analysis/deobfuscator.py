"""Conservative static JavaScript deobfuscation helpers."""

from __future__ import annotations

import ast
import base64
import json
import re
from typing import Any


def deobfuscate(source: str) -> dict[str, Any]:
    transformations = {"strings_replaced": 0, "dead_branches_removed": 0, "control_flows_recovered": 0, "variables_renamed": 0, "iifes_expanded": 0}
    code, count = _replace_string_decoders(source)
    transformations["strings_replaced"] += count
    code, count = _decode_base64_array_values(code)
    transformations["strings_replaced"] += count
    code, count = _replace_direct_array_refs(code)
    transformations["strings_replaced"] += count
    code, count = _remove_dead_branches(code)
    transformations["dead_branches_removed"] = count
    code, blocks, count = _recover_control_flow(code)
    transformations["control_flows_recovered"] = count
    code, count = _expand_iifes(code)
    transformations["iifes_expanded"] = count
    code, rename_map = _rename_api_variables(code)
    transformations["variables_renamed"] = len(rename_map)
    return {"code": _normalize_spacing(code).strip(), "transformations": transformations, "basic_blocks": blocks, "rename_map": rename_map, "warnings": [], "confidence": "high" if sum(transformations.values()) else "none"}


def _parse_string_array(body: str) -> list[str] | None:
    try:
        values = ast.literal_eval("[" + body + "]")
    except (SyntaxError, ValueError):
        return None
    return values if isinstance(values, list) and all(isinstance(item, str) for item in values) else None


def _replace_string_decoders(source: str) -> tuple[str, int]:
    arrays = {}
    for match in re.finditer(r"\b(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*\[([\s\S]*?)\]\s*;", source):
        values = _parse_string_array(match.group(2))
        if values is not None:
            arrays[match.group(1)] = values
    decoders = {}
    pattern = re.compile(r"\bfunction\s+(_0x[a-fA-F0-9]+)\s*\(\s*([\w$]+)\s*\)\s*\{\s*return\s+(_0x[a-fA-F0-9]+)\s*\[\s*\2\s*(?:-\s*(0x[0-9a-fA-F]+|\d+))?\s*\]\s*;?\s*\}")
    for match in pattern.finditer(source):
        if match.group(3) in arrays:
            decoders[match.group(1)] = (arrays[match.group(3)], int(match.group(4), 0) if match.group(4) else 0)
    count = 0
    for name, (values, offset) in decoders.items():
        def replace(match: re.Match[str]) -> str:
            nonlocal count
            index = int(match.group(1), 0) - offset
            if not 0 <= index < len(values):
                return match.group(0)
            count += 1
            return json.dumps(values[index], ensure_ascii=False)
        source = re.sub(rf"\b{re.escape(name)}\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", replace, source)
    return source, count


def _decode_base64_array_values(source: str) -> tuple[str, int]:
    count = 0
    pattern = re.compile(r"(['\"])([A-Za-z0-9+/]{8,}={0,2})\1")
    def replace(match: re.Match[str]) -> str:
        nonlocal count
        try:
            decoded = base64.b64decode(match.group(2), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)
        if not any(char in decoded for char in "/:_-. "):
            return match.group(0)
        count += 1
        return json.dumps(decoded, ensure_ascii=False)
    return pattern.sub(replace, source), count


def _replace_direct_array_refs(source: str) -> tuple[str, int]:
    arrays = {}
    for match in re.finditer(r"\b(?:var|let|const)\s+(_0x[\w$]+)\s*=\s*\[([\s\S]*?)\]\s*;", source):
        values = _parse_string_array(match.group(2))
        if values is not None:
            arrays[match.group(1)] = values
    count = 0
    for name, values in arrays.items():
        def replace(match: re.Match[str]) -> str:
            nonlocal count
            index = int(match.group(1), 0)
            if not 0 <= index < len(values):
                return match.group(0)
            count += 1
            return json.dumps(values[index], ensure_ascii=False)
        source = re.sub(rf"\b{re.escape(name)}\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]", replace, source)
    return source, count


def _remove_dead_branches(source: str) -> tuple[str, int]:
    count = 0
    pattern = re.compile(r"\bif\s*\((false|true|!!\[\]|!\[\])\)\s*\{")
    position = 0
    while match := pattern.search(source, position):
        condition = match.group(1) in {"true", "!![]"}
        close = _matching_brace(source, source.find("{", match.start()))
        if close is None:
            break
        body = source[source.find("{", match.start()) + 1:close]
        cursor = close + 1
        whitespace = re.match(r"\s*", source[cursor:]).group(0)
        else_start = cursor + len(whitespace)
        replacement = body if condition else ""
        end = close + 1
        if source.startswith("else", else_start):
            opening = source.find("{", else_start + 4)
            closing = _matching_brace(source, opening) if opening >= 0 else None
            if closing is not None:
                replacement = body if condition else source[opening + 1:closing]
                end = closing + 1
        source = source[:match.start()] + replacement + source[end:]
        count += 1
        position = match.start() + len(replacement)
    return source, count


def _recover_control_flow(source: str) -> tuple[str, list[str], int]:
    match = re.search(r"while\s*\(\s*true\s*\)\s*\{", source)
    if not match:
        return source, [], 0
    loop_close = _matching_brace(source, source.find("{", match.start()))
    body = source[source.find("{", match.start()) + 1:loop_close] if loop_close is not None else ""
    switch = re.search(r"switch\s*\(\s*([\w$]+)\s*\)\s*\{", body)
    initial = re.findall(r"\b(?:var|let|const)\s+([\w$]+)\s*=\s*(\d+)", source[:match.start()])
    if not switch or not initial or loop_close is None:
        return source, [], 0
    state_name, state = switch.group(1), initial[-1][1]
    switch_open = body.find("{", switch.start())
    switch_close = _matching_brace(body, switch_open)
    cases = _parse_cases(body[switch_open + 1:switch_close]) if switch_close is not None else {}
    blocks, visited = [], set()
    while state in cases and state not in visited:
        visited.add(state)
        current = cases[state]
        next_state = re.search(rf"\b{re.escape(state_name)}\s*=\s*(\d+)", current)
        cleaned = re.sub(rf"\b{re.escape(state_name)}\s*=\s*\d+\s*;", "", current)
        cleaned = re.sub(r"\b(?:continue|break)\s*;", "", cleaned).strip()
        if cleaned:
            blocks.append(cleaned)
        if not next_state:
            break
        state = next_state.group(1)
    if not blocks:
        return source, [], 0
    return source[:match.start()] + "\n".join(blocks) + source[loop_close + 1:], blocks, 1


def _parse_cases(body: str) -> dict[str, str]:
    matches = list(re.finditer(r"\bcase\s+(\d+)\s*:", body))
    return {m.group(1): body[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(body)].strip() for i, m in enumerate(matches)}


def _expand_iifes(source: str) -> tuple[str, int]:
    count = 0
    pattern = re.compile(r"\(\s*function\s*\(\s*\)\s*\{")
    position = 0
    while match := pattern.search(source, position):
        opening = source.find("{", match.start())
        closing = _matching_brace(source, opening)
        suffix = re.match(r"\s*\)\s*\(\s*\)\s*;?", source[closing + 1:]) if closing is not None else None
        if closing is None or suffix is None:
            position = match.end()
            continue
        body = source[opening + 1:closing].strip()
        source = source[:match.start()] + body + source[closing + 1 + suffix.end():]
        count += 1
        position = match.start() + len(body)
    return source, count


def _rename_api_variables(source: str) -> tuple[str, dict[str, str]]:
    mapping = {}
    for name in re.findall(r"\b(_0x[\w$]+)\b", source):
        if re.search(rf"\b{re.escape(name)}\s*=\s*new\s+XMLHttpRequest\b", source):
            mapping.setdefault(name, "xhr")
        elif re.search(rf"\b{re.escape(name)}\s*=\s*axios\.create\s*\(", source):
            mapping.setdefault(name, "apiClient")
        elif re.search(rf"\b{re.escape(name)}\s*=\s*(?:localStorage|sessionStorage)\.getItem\s*\([^)]*(?:token|auth|key)", source, re.I):
            mapping.setdefault(name, "authToken")
    for old, new in mapping.items():
        source = re.sub(rf"\b{re.escape(old)}\b", new, source)
    return source, mapping


def _matching_brace(source: str, start: int) -> int | None:
    depth, quote, escaped = 0, None, False
    for index in range(start, len(source)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _normalize_spacing(source: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+\n", "\n", source))
