# Hunter v8.1 hunter_tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development or executing-plans task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reverse_lab_tools-style Hunter facade and MCP entrypoints for Hunter KB and Burp bridge.

**Architecture:** Keep `mcp_server.py` compatible. Add `core/hunter_tools_facade.py` as the testable implementation and `hunter_tools_mcp.py` as a new unified MCP server entrypoint.

**Tech Stack:** Python 3, FastMCP, pytest, existing `PayloadLoader`, existing `BurpBridge`.

---

### Task 1: Facade RED tests

**Files:**
- Create: `tests/test_hunter_tools_facade.py`
- Modify: none

- [x] Write tests for KB list/search/read, path traversal blocking, Burp plans, recommendation enrichment.
- [x] Run `python -m pytest tests/test_hunter_tools_facade.py -q` and verify failures due to missing `core.hunter_tools_facade`.

### Task 2: MCP wrapper RED tests

**Files:**
- Create: `tests/test_hunter_tools_mcp.py`
- Modify: none

- [x] Write tests for new root `mcp_server.py` functions and standalone `hunter_tools_mcp.py` functions.
- [x] Run focused pytest and verify missing wrappers fail.

### Task 3: Implement facade GREEN

**Files:**
- Create: `core/hunter_tools_facade.py`

- [ ] Implement structured JSON envelope helpers.
- [ ] Implement payloads markdown/YAML inventory and safe path resolution.
- [ ] Implement simple deterministic BM25-like scoring by token count/title/path/snippet.
- [ ] Implement BurpBridge action wrappers.
- [ ] Implement capability and health payloads.
- [ ] Implement recommendation enrichment.

### Task 4: Implement MCP wrappers GREEN

**Files:**
- Modify: `mcp_server.py`
- Create: `hunter_tools_mcp.py`

- [ ] Instantiate `HunterToolsFacade` once.
- [ ] Register `hunter_kb_*` and `hunter_burp_*` tools in existing server.
- [ ] Register same tools in `hunter_tools_mcp.py` with server name `hunter_tools`.
- [ ] Extend existing `hunter_healthcheck`, `hunter_capabilities`, `hunter_recommend_next` with facade data.

### Task 5: Docs, state, verification

**Files:**
- Modify: `SKILL.md`, `README.md`, `TOOLS.md`
- Modify: `D:\Open-tgtylab\cases\hunter-skill\state.json`
- Create: `D:\Open-tgtylab\exports\notes\hunter-tools-v81-result-20260710.md`

- [ ] Run full pytest.
- [ ] Run direct async function smoke tests.
- [ ] Sync Codex skill copy if separate.
- [ ] Commit changes and record evidence.
