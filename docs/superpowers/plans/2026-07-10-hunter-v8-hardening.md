# Hunter v8 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Hunter MCP into a stable, introspectable, evidence-driven framework.

**Architecture:** Add tests first for MCP registration, wrapper behavior, capability/health outputs, recommendation routing, and payload portability. Then update `mcp_server.py`, payload tests, and docs with minimal focused changes.

**Tech Stack:** Python 3.14, pytest, FastMCP, PowerShell, Git.

---

## File Map
- Modify: `mcp_server.py` — MCP tool registration, safe helpers, health/capability/recommendation tools.
- Modify: `tests/test_payloads.py` — Windows-safe UTF-8 loading and dynamic actual payload inventory checks.
- Create: `tests/test_mcp_v8_hardening.py` — regression tests for v8 wrappers and metadata tools.
- Modify: `SKILL.md`, `README.md`, `TOOLS.md` — actual tool list and workflow.

## Tasks

### Task 1: Write failing MCP v8 tests
- [ ] Add tests that assert missing v8 tool functions exist.
- [ ] Add monkeypatched tests for `hunter_auto_ssti`, `hunter_auto_cmd`, `hunter_auto_idor`, and new auto wrappers.
- [ ] Add tests for `hunter_healthcheck`, `hunter_capabilities`, and `hunter_recommend_next` JSON shape.
- [ ] Run `python -m pytest -q tests/test_mcp_v8_hardening.py` and confirm failures before implementation.

### Task 2: Implement MCP v8 hardening
- [ ] Add JSON helper and safe async/thread wrappers in `mcp_server.py`.
- [ ] Register missing auto tools with the real implementation names.
- [ ] Correct `ssti`, `cmd`, and `idor` wrappers.
- [ ] Add healthcheck/capabilities/recommendation tools.
- [ ] Run targeted MCP tests and confirm pass.

### Task 3: Fix payload portability
- [ ] Update `tests/test_payloads.py` to use `encoding='utf-8'`.
- [ ] Replace stale fixed directory expectations with actual inventory plus minimum required core types.
- [ ] Run `python -m pytest -q tests/test_payloads.py` and confirm pass.

### Task 4: Update docs and skill
- [ ] Update `SKILL.md` tool count, workflow, and degraded-scan guidance.
- [ ] Update `README.md`/`TOOLS.md` with v8 health/capability tools.
- [ ] Run grep checks for stale `27 个工具` and missing v8 tool names.

### Task 5: Full verification
- [ ] Run `python -m pytest -q`.
- [ ] Run lightweight direct calls for `hunter_healthcheck`, `hunter_capabilities`, and `hunter_recommend_next`.
- [ ] Save summary to `D:\Open-tgtylab\exports\notes\hunter-v8-hardening-result-20260710.md`.
