# curl_cffi Stealth Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make curl_cffi the default StealthHTTPClient transport with persisted browser impersonation and a one-time requests fallback warning.

**Architecture:** Extend fingerprint records with curl-compatible impersonation metadata, then make StealthHTTPClient create its default transport from the persisted session state. Keep injected transport factories untouched and retain a separate reference to native requests for fallback-only behavior.

**Tech Stack:** Python, curl_cffi requests API, native requests fallback, pytest, PEP 621 TOML.

---

### Task 1: Add failing backend and fingerprint tests

**Files:**
- Create: `tests/test_stealth_curl_transport.py`
- Modify: `tests/test_stealth_foundation.py`

- [ ] Test curl-present and curl-blocked import scenarios in fresh subprocesses.
- [ ] Test the six curl 0.6 baseline impersonation mappings.
- [ ] Test that every fingerprint contains an `impersonate` key and Firefox uses `None`.
- [ ] Test default curl Session receives the persisted impersonate value.
- [ ] Test constructor/session overrides and unchanged custom transport factory signature.
- [ ] Test fallback warning is emitted exactly once.
- [ ] Run `python -m pytest tests/test_stealth_curl_transport.py tests/test_stealth_foundation.py -v` and verify failures are caused by missing behavior.

### Task 2: Implement fingerprint metadata

**Files:**
- Modify: `core/stealth/fingerprint_manager.py`

- [ ] Add `CURL_IMPERSONATE_MAPPINGS` with Chrome 110/120, Edge 99/101, Safari 15/17 targets.
- [ ] Add nearest-supported target lookup by browser/version.
- [ ] Store `impersonate` on preset and imported fingerprints.
- [ ] Add `require_impersonate` filtering to `choose` and `for_session`.
- [ ] Re-run focused fingerprint tests.

### Task 3: Implement curl_cffi transport selection

**Files:**
- Modify: `core/stealth/stealth_http_client.py`

- [ ] Prefer curl_cffi requests import and preserve native requests reference.
- [ ] Add module backend flag, logger, and one-time fallback warning.
- [ ] Make default transport state-aware and initialize curl Session with impersonate.
- [ ] Persist and restore session impersonate with explicit override precedence.
- [ ] Use backend-specific Cookie jars.
- [ ] Keep custom factory and native requests chunked detection compatible.
- [ ] Add impersonate to request timeline.
- [ ] Run curl transport, stealth client, and strategy execution tests.

### Task 4: Add optional dependency and verify

**Files:**
- Create: `pyproject.toml`

- [ ] Add minimal project metadata and `stealth = ["curl_cffi>=0.6.0"]`.
- [ ] Run `python -m pip install "curl_cffi>=0.6.0"`.
- [ ] Run focused stealth tests.
- [ ] Run `python -m pytest tests/ -v`.
- [ ] Run py_compile and `git diff --check`.
- [ ] Write evidence note and update `cases/hunter-skill/state.json`.

