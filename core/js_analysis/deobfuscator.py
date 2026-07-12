"""Safe, pattern-driven JavaScript deobfuscation.

Transforms are deliberately limited to constructs whose result can be proven from
local source text. Unrecognized code is preserved unchanged.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any


def deobfuscate(source: str) -> dict[str, Any]:
    code = source
    transformations = {
        "strings_replaced": 0,
        "dead_branches_removed": 0,
        "control_flows_recovered": 0,
        "variables_renamed": 0,
        "iifes_expanded": 0,
    }
    warnings = []

    code, count = _replace_string_decoders(code)
    transformations["strings_replaced"] += count
    code, count = _remove_dead_branches(code)
    transformations["dead_branches_removed"] += count
    code, basic_blocks, count = _recover_control_flow(code)
    transformations["control_flows_recovered"] += count
    code, count = _expand_iifes(code)
    transformations["iifes_expanded"] += count

    return {
        "code": _normalize_spacing(code).strip(),
        "transformations": transformations,
        "basic_blocks": basic_blocks,
        "warnings": warnings,
        "confidence": "high" if sum(transformations.values()) else "none",
    }


def _replace_string_decoders(source: str) -> tuple[str, int]:
    arrays: dict[str, list[str]] = {}
    array_pattern = re.compile(r"\b(var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*\[([\s\S]*?)\]\s*;")
    for match in array_pattern.finditer(source):
        values = _parse_string_array(match.group(3))
        if values is not None:
            arrays[match.group(2)] = values

    decoders: dict[str, tuple[list[str], int]] = {}
    function_pattern = re.compile(
        r"\bfunction\s+(_0x[a-fA-F0-9]+)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{\s*"
        r"return\s+(_0x[a-fA-F0-9]+)\s*\[\s*\2\s*(?:-\s*(0x[0-9a-fA-F]+|\d+))?\s*\]\s*;?\s*\}"
    )
    for match in function_pattern.finditer(source):
        array = arrays.get(match.group(3))
        if array is not None:
            offset = int(match.group(4), 0) if match.group(4) else 0
            decoders[match.group(1)] = (array, offset)

    replacements = 0
    for decoder, (values, offset) in decoders.items():
        call_pattern = re.compile(rf"\b{re.escape(decoder)}\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)")

        def replace_call(match: re.Match[str]) -> str:
            nonlocal replacements
            index = int(match.group(1), 0) - offset
            if not 0 <= index < len(values):
                return match.group(0)
            replacements += 1
            return json.dumps(values[index], ensure_ascii=False)

        source = call_pattern.sub(replace_call, source)
    return source, replacements


def _parse_string_array(body: str) -> list[str] | None:
    try:
        parsed = ast.literal_eval("[" + body + "]")
    except (SyntaxError, ValueError):
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        return None
    return parsed


def _remove_dead_branches(source: str) -> tuple[str, int]:
    count = 0
    pattern = re.compile(r"\bif\s*\((false|true|!!\[\]|!\[\])\)\s*\{")
    position = 0
    while True:
        match = pattern.search(source, position)
        if not match:
            break
        condition = match.group(1) in {"true", "!![]"}
        then_open = source.find("{", match.start())
        then_close = _matching_brace(source, then_open)
        if then_close is None:
            position = match.end()
            continue
        then_body = source[then_open + 1 : then_close]
        cursor = then_close + 1
        whitespace = re.match(r"\s*", source[cursor:]).group(0)
        else_start = cursor + len(whitespace)
        else_body = ""
        replace_end = then_close + 1
        if source.startswith("else", else_start):
            else_open = source.find("{", else_start + 4)
            if else_open != -1:
                else_close = _matching_brace(source, else_open)
                if else_close is not None:
                    else_body = source[else_open + 1 : else_close]
                    replace_end = else_close + 1
        replacement = then_body if condition else else_body
        source = source[: match.start()] + replacement + source[replace_end:]
        count += 1
        position = match.start() + len(replacement)
    return source, count


def _recover_control_flow(source: str) -> tuple[str, list[str], int]:
    loop_pattern = re.compile(r"while\s*\(\s*true\s*\)\s*\{")
    match = loop_pattern.search(source)
    if not match:
        return source, [], 0
    loop_open = source.find("{", match.start())
    loop_close = _matching_brace(source, loop_open)
    if loop_close is None:
        return source, [], 0
    loop_body = source[loop_open + 1 : loop_close]
    switch_match = re.search(r"switch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{", loop_body)
    if not switch_match:
        return source, [], 0
    state_name = switch_match.group(1)
    switch_open = loop_body.find("{", switch_match.start())
    switch_close = _matching_brace(loop_body, switch_open)
    if switch_close is None:
        return source, [], 0
    initial_matches = list(re.finditer(rf"\b(?:var|let|const)\s+{re.escape(state_name)}\s*=\s*(\d+)\s*;", source[: match.start()]))
    if not initial_matches:
        return source, [], 0
    state = initial_matches[-1].group(1)
    cases = _parse_cases(loop_body[switch_open + 1 : switch_close])
    blocks = []
    visited = set()
    while state in cases and state not in visited:
        visited.add(state)
        body = cases[state]
        transition = re.search(rf"\b{re.escape(state_name)}\s*=\s*(\d+)\s*;", body)
        cleaned = re.sub(rf"\b{re.escape(state_name)}\s*=\s*\d+\s*;", "", body)
        cleaned = re.sub(r"\b(?:continue|break)\s*;", "", cleaned).strip()
        if cleaned:
            blocks.append(cleaned)
        if not transition:
            break
        state = transition.group(1)
    if not blocks:
        return source, [], 0
    replacement = "\n".join(blocks)
    source = source[: match.start()] + replacement + source[loop_close + 1 :]
    return source, blocks, 1


def _parse_cases(body: str) -> dict[str, str]:
    matches = list(re.finditer(r"\bcase\s+(\d+)\s*:", body))
    return {
        match.group(1): body[match.end() : matches[index + 1].start() if index + 1 < len(matches) else len(body)].strip()
        for index, match in enumerate(matches)
    }


def _expand_iifes(source: str) -> tuple[str, int]:
    pattern = re.compile(r"\(\s*function\s*\(\s*\)\s*\{")
    count = 0
    position = 0
    while True:
        match = pattern.search(source, position)
        if not match:
            break
        body_open = source.find("{", match.start())
        body_close = _matching_brace(source, body_open)
        if body_close is None:
            break
        suffix = re.match(r"\s*\)\s*\(\s*\)\s*;?", source[body_close + 1 :])
        if not suffix:
            position = body_close + 1
            continue
        end = body_close + 1 + suffix.end()
        body = source[body_open + 1 : body_close].strip()
        source = source[: match.start()] + body + source[end:]
        count += 1
        position = match.start() + len(body)
    return source, count


def _matching_brace(source: str, start: int) -> int | None:
    depth = 0
    quote = None
    escaped = False
    for index in range(start, len(source)):
        char = source[index]
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
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _normalize_spacing(source: str) -> str:
    source = re.sub(r"[ \t]+\n", "\n", source)
    source = re.sub(r"\n{3,}", "\n\n", source)
    return source
