# FFUF Readable Results Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode Base64 path values in ffuf directory-enumeration output and add a readable status-grouped summary without changing legacy raw fields.

**Architecture:** Add small pure helpers in `mcp_server.py` for Base64 text validation, URL-path normalization, record copying, and summary rendering. Wire those helpers only into the `dir-enum` branch, preserving raw `results` and `stdout_preview` while adding `parsed_results` and `human_readable`.

**Tech Stack:** Python standard library (`base64`, `binascii`, `urllib.parse`), pytest, FastMCP-compatible JSON payloads.

---

### Task 1: Add failing parser tests

**Files:**
- Create: `tests/test_dir_enum_parsing.py`
- Read: `mcp_server.py:580-611`
- Read: `mcp_server.py:824-833`

- [ ] **Step 1: Test standard and URL-safe Base64 URL decoding**

Create records containing:

```python
{
    "url": "https://target.test/LndlbGwta25vd24vYnJvd3Nlcmlk?source=ffuf#hit",
    "status": 200,
    "input": {"FUZZ": "LndlbGwta25vd24vYnJvd3Nlcmlk"},
}
```

Assert `parsed_results[0]["url"]` is
`https://target.test/.well-known/browserid?source=ffuf#hit` and
`parsed_results[0]["raw_url"]` is the original URL. Add a URL-safe token produced
from `"路径/测试"` and assert it decodes.

- [ ] **Step 2: Test invalid and binary candidates**

Assert `/admin/`, invalid Base64, and Base64 that decodes to `b"\x00\xff\x01"` remain
unchanged while still receiving `raw_url`.

- [ ] **Step 3: Test summary and compatibility**

Patch `_hunter.ffuf_fuzz` to return JSON lines. Assert:

```python
payload["results"] == raw_records
payload["stdout_preview"] == raw_stdout
payload["parsed_results"][0]["url"] == decoded_url
"HTTP 302" in payload["human_readable"]
" -> https://target.test/login" in payload["human_readable"]
```

Add one `<20` fixture where 404 appears and one `>=20` fixture where 404 is absent.

- [ ] **Step 4: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_dir_enum_parsing.py -v
```

Expected: failure because `parsed_results` and `human_readable` do not exist.

### Task 2: Implement URL decoding helpers

**Files:**
- Modify: `mcp_server.py:15-35`
- Modify: `mcp_server.py:572-611`
- Test: `tests/test_dir_enum_parsing.py`

- [ ] **Step 1: Add standard-library imports**

Add `base64` and `binascii`, plus `quote`, `unquote`, `urlsplit`, and `urlunsplit`
from `urllib.parse`.

- [ ] **Step 2: Implement strict Base64 text decoding**

Add:

```python
def _decode_base64_text(value: str) -> Optional[str]:
    token = unquote(value).strip()
    if len(token) < 4 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", token):
        return None
    padded = token + ("=" * (-len(token) % 4))
    for altchars in (None, b"-_"):
        try:
            decoded = base64.b64decode(padded, altchars=altchars, validate=True)
            text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        standard = base64.b64encode(decoded).decode("ascii").rstrip("=")
        urlsafe = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        if token.rstrip("=") not in {standard, urlsafe}:
            continue
        if text and all(char.isprintable() for char in text):
            return text
    return None
```

- [ ] **Step 3: Implement record normalization**

Add helpers that copy each record, save `raw_url`, prefer `input` candidates, fall
back to individual path segments, replace only the path, and preserve query/fragment.

- [ ] **Step 4: Run focused parser tests**

Run:

```powershell
python -m pytest tests/test_dir_enum_parsing.py -v
```

Expected: URL decoding tests pass; summary tests still fail until Task 3.

### Task 3: Implement grouped human-readable summary

**Files:**
- Modify: `mcp_server.py:572-650`
- Modify: `mcp_server.py:824-833`
- Test: `tests/test_dir_enum_parsing.py`

- [ ] **Step 1: Add summary helper**

Group normalized records by integer/string status. Use all records when the total is
less than 20; otherwise exclude status 404. Render redirect targets with `urljoin`.

- [ ] **Step 2: Wire helpers into dir-enum**

Keep:

```python
"results": records[:200],
```

Add:

```python
"parsed_results": parsed_records[:200],
"human_readable": _summarize_ffuf_results(parsed_records),
```

- [ ] **Step 3: Run focused tests and verify GREEN**

Run:

```powershell
python -m pytest tests/test_dir_enum_parsing.py -v
```

Expected: all tests pass.

### Task 4: Regression verification and evidence

**Files:**
- Modify: `D:\Open-tgtylab\cases\hunter-skill\state.json`
- Create: `D:\Open-tgtylab\exports\notes\hunter-ffuf-readable-results-20260713.md`

- [ ] **Step 1: Run related MCP tests**

Run:

```powershell
python -m pytest tests/test_dir_enum_parsing.py tests/test_hunter_tools_complete.py tests/test_mcp_v8_hardening.py -v
```

- [ ] **Step 2: Run full suite**

Run:

```powershell
python -m pytest tests/ -v
```

Expected: all collected tests pass.

- [ ] **Step 3: Run static checks**

Run:

```powershell
python -m py_compile mcp_server.py tests/test_dir_enum_parsing.py
git diff --check -- mcp_server.py tests/test_dir_enum_parsing.py
```

- [ ] **Step 4: Persist evidence**

Record exact test counts, compatibility fields, decoding behavior, and any unrelated
environmental flake in the evidence note and case state.

