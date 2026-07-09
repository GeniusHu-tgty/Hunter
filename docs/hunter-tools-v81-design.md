# Hunter v8.1 `hunter_tools` Design

## Goal

Turn Hunter from a single compatibility MCP server into a `reverse_lab_tools`-style unified tool layer named `hunter_tools`, while keeping the existing `mcp_server.py` tools compatible.

## Architecture

`core/hunter_tools_facade.py` becomes the pure-Python facade. It owns structured outputs for:

- Hunter technique KB discovery/search/read over `payloads/**/*.md`.
- Payload inventory/search/read via the existing `PayloadLoader`.
- Burp bridge plan generation via the existing `core.burp_bridge.BurpBridge`.
- Tool capability and health metadata that can be embedded into `hunter_healthcheck` and `hunter_capabilities`.
- Recommendation enrichment that combines signal routing, KB hits, payload matches and Burp workflow suggestions.

`hunter_tools_mcp.py` becomes a reverse_lab_tools-style MCP entrypoint. It exposes the same facade capabilities under `hunter_*` names so the current skill can discover them after MCP reload. The root `mcp_server.py` also imports the facade and registers the same tools for backward compatibility.

## Tool API

New MCP tools:

- `hunter_kb_list()` -> categories, markdown files, payload YAML files, totals.
- `hunter_kb_search(query, limit=20)` -> ranked markdown/YAML hits with path, title, score, snippets.
- `hunter_kb_read(technique_path, max_chars=12000)` -> exact KB file content and metadata, path constrained to `payloads/`.
- `hunter_kb_recommend(signals=None, finding="", limit=8)` -> KB hits + payload hits + suggested Hunter/Burp next tools.
- `hunter_burp_bridge(action, ...)` -> generic Burp bridge plan envelope.
- `hunter_burp_repeater(...)` -> create Repeater plan.
- `hunter_burp_proxy_search(regex, ...)` -> proxy history search plan.
- `hunter_burp_scanner_issues(...)` -> scanner issues plan.
- `hunter_burp_collaborator_workflow(workflow, ...)` -> blind SSRF/XXE/CMDI workflow plan.

All tools return JSON dictionaries with at least:

```json
{
  "tool": "hunter_kb_search",
  "status": "ok",
  "data": {},
  "evidence": {},
  "next_actions": []
}
```

Errors are returned as JSON with `status=error`, `error_type`, and `error`; exceptions must not leak into MCP transport for normal invalid input.

## ReverseLab compatibility rules

- KB routes look like `category/file.md`, mirroring `kb_read_file` path style.
- Health/capabilities include `tool_style: reverse_lab_tools-compatible`.
- Evidence outputs point to Hunter `evidence/tool_output` or caller-supplied paths.
- Burp plans are explicit MCP action plans, because Python cannot directly invoke another MCP server.
- HTTP execution remains delegated to Burp `send_http2_request` or project `http_probe`; Hunter only plans and packages evidence.

## Testing

TDD tests cover facade behavior first, then MCP wrappers:

- KB inventory lists markdown and payload YAML.
- KB search ranks `jwt`, `ssrf`, `sqli` docs and snippets.
- KB read blocks path traversal.
- Burp bridge plans call existing `BurpBridge` methods with stable schema.
- Capabilities/health include new tools.
- Recommendation includes KB/payload/Burp suggestions.
