# Stealth Fingerprint Persistence and Adaptive Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep a stable browser fingerprint for every stealth session, rotate to a different browser family on explicit or narrowly defined automatic signals, retry within the existing budget, and classify fingerprint versus IP/target blocking with a bounded health probe.

**Architecture:** `FingerprintManager` owns fixed session bindings and cross-family candidate selection. `StealthHTTPClient` owns persisted counters, transport refresh, adaptive retry decisions, audit events, and direct health probes. Existing request, WAF, proxy, CAPTCHA, cookie, CSRF, and MCP contracts remain intact.

**Tech Stack:** Python 3, pytest, requests/curl-cffi compatible transports, JSON session persistence.

---

### Task 1: Fixed Manager Binding and Cross-Family Rotation

**Files:**
- Modify: `tests/test_stealth_foundation.py`
- Modify: `tests/test_stealth_curl_transport.py`
- Modify: `core/stealth/fingerprint_manager.py`

- [ ] **Step 1: Write failing manager tests**

Add focused tests equivalent to:

```python
def test_for_session_never_silently_replaces_existing_fingerprint():
    manager = FingerprintManager(seed=5)
    firefox = next(x for x in manager.fingerprints() if x["browser"] == "Firefox")
    manager.bind_session("stealth-fixed", firefox["id"])

    assert manager.for_session("stealth-fixed")["id"] == firefox["id"]
    with pytest.raises(RuntimeError, match="rotate_fingerprint"):
        manager.for_session("stealth-fixed", require_impersonate=True)
    assert manager.for_session("stealth-fixed")["id"] == firefox["id"]


def test_rotate_fingerprint_changes_browser_family_and_binding():
    manager = FingerprintManager(seed=7)
    first = manager.for_session("stealth-rotate")

    second = manager.rotate_fingerprint(
        "stealth-rotate",
        current_fingerprint_id=first["id"],
    )

    assert second["id"] != first["id"]
    assert second["browser"] != first["browser"]
    assert manager.for_session("stealth-rotate")["id"] == second["id"]
```

Revise the prior curl compatibility expectation so an already bound
non-impersonatable fingerprint raises instead of silently changing identity.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_stealth_foundation.py tests/test_stealth_curl_transport.py -k "for_session or rotate_fingerprint or non_impersonatable" -q
```

Expected: failures because `bind_session()` and `rotate_fingerprint()` do not
exist and `for_session()` still silently replaces the binding.

- [ ] **Step 3: Implement the minimal manager API**

Implement:

```python
def bind_session(self, session_id, fingerprint_id):
    item = self.get(fingerprint_id)
    self.sessions[str(session_id)] = item["id"]
    return item

def for_session(self, session_id, strategy="random", require_impersonate=False):
    current = self.sessions.get(str(session_id))
    if current:
        item = self.get(current)
        if require_impersonate and not item.get("impersonate"):
            raise RuntimeError(
                "session fingerprint does not support impersonation; "
                "call rotate_fingerprint() explicitly"
            )
        return item
    item = self.choose(strategy, require_impersonate=require_impersonate)
    self.sessions[str(session_id)] = item["id"]
    return item

def rotate_fingerprint(
    self,
    session_id,
    *,
    current_fingerprint_id=None,
    strategy="random",
    require_impersonate=False,
):
    current_id = current_fingerprint_id or self.sessions.get(str(session_id))
    current = self.get(current_id) if current_id else None
    candidates = [
        item
        for item in self.pool
        if (current is None or item["browser"] != current["browser"])
        and (not require_impersonate or item.get("impersonate"))
    ]
    if not candidates:
        raise RuntimeError("no cross-family fingerprint candidate is available")
    if strategy == "round-robin":
        selected = candidates[self.index % len(candidates)]
        self.index += 1
    else:
        selected = self.random.choice(candidates)
    self.sessions[str(session_id)] = selected["id"]
    return deepcopy(selected)
```

- [ ] **Step 4: Run tests and verify GREEN**

Run the command from Step 2. Expected: all selected tests pass.

### Task 2: Session Persistence and Manual Rotation

**Files:**
- Modify: `tests/test_stealth_client.py`
- Modify: `tests/test_stealth_curl_transport.py`
- Modify: `core/stealth/stealth_http_client.py`

- [ ] **Step 1: Write failing session tests**

Add tests equivalent to:

```python
def test_repeated_requests_and_restore_keep_one_fingerprint(tmp_path):
    first_transport = Transport([Response(), Response()])
    first = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: first_transport,
        sleep=lambda _: None,
    )
    created = first.session_create("https://fixture", resume=False)
    first.stealth_request("GET", "https://fixture/a", options={"max_retries": 0})
    first.stealth_request("GET", "https://fixture/b", options={"max_retries": 0})

    restored = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: Transport([]),
        sleep=lambda _: None,
    )
    state = restored.session_create("https://fixture", resume=True)

    assert state["fingerprint_id"] == created["fingerprint_id"]
    assert first_transport.calls[0][2]["headers"]["User-Agent"] == (
        first_transport.calls[1][2]["headers"]["User-Agent"]
    )


def test_manual_rotation_changes_family_and_records_state(tmp_path):
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: Transport([]),
        sleep=lambda _: None,
    )
    before = client.session_create("https://fixture", resume=False)

    event = client.rotate_fingerprint("https://fixture", reason="manual-test")
    after = client.session_state("https://fixture")

    assert event["previous_browser"] != event["new_browser"]
    assert before["fingerprint_id"] != after["fingerprint_id"]
    assert after["fingerprint_rotation_count"] == 1
    assert after["fingerprint_rotations"][-1]["reason"] == "manual-test"
```

Add a `DetectionSession.rotate_fingerprint()` delegation test. Revise legacy
restore tests to assert exact fingerprint persistence rather than silent
migration.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_stealth_client.py tests/test_stealth_curl_transport.py -k "fingerprint and (restore or rotation or repeated or legacy)" -q
```

Expected: failures because session binding restore, state fields, and public
rotation APIs are missing.

- [ ] **Step 3: Implement state initialization and rotation**

Add helpers with these contracts:

```python
def _ensure_fingerprint_state(self, state):
    state.setdefault("fingerprint_rotation_count", 0)
    state.setdefault("fingerprint_rotations", [])
    failures = state.setdefault("fingerprint_failures", {})
    failures.setdefault("gateway", 0)
    failures.setdefault("timeout", 0)
    self.fingerprints.bind_session(state["session_id"], state["fingerprint_id"])
    return state

def _runtime_by_identity(self, target=None, session_id=None):
    if bool(target) == bool(session_id):
        raise ValueError("provide exactly one of target or session_id")
    runtime = (
        self._runtime_for_session_id(session_id)
        if session_id
        else self._runtime(target)
    )
    if runtime is None:
        raise LookupError(f"Stealth session '{session_id}' not found")
    return runtime
```

Generate `session_id` before calling:

```python
self.fingerprints.for_session(
    state["session_id"],
    strategy=fingerprint_strategy,
    require_impersonate=require_impersonate,
)
```

During
restore, call `_ensure_fingerprint_state()` and never replace
`state["fingerprint_id"]` in `_prepare_transport_state()`.

Implement an internal runtime rotation helper and public wrapper. Rotation must
record:

```python
event = {
    "at": time.time(),
    "reason": str(reason),
    "automatic": bool(automatic),
    "previous_fingerprint_id": previous["id"],
    "new_fingerprint_id": selected["id"],
    "previous_browser": previous["browser"],
    "new_browser": selected["browser"],
    "count": state["fingerprint_rotation_count"],
}
```

Default transports are rebuilt with the new `impersonate`, and state cookies
are restored. Custom transports remain in place.

Add:

```python
def rotate_fingerprint(self, target=None, *, session_id=None,
                       reason="manual", automatic=False):
    runtime = self._runtime_by_identity(target, session_id)
    return deepcopy(
        self._rotate_runtime_fingerprint(runtime, reason, automatic)
    )
```

Add:

```python
def rotate_fingerprint(self, reason="manual"):
    return self.client.rotate_fingerprint(
        session_id=self.session_id,
        reason=reason,
    )
```

to `DetectionSession`.

- [ ] **Step 4: Run tests and verify GREEN**

Run the command from Step 2, then:

```powershell
python -m pytest tests/test_stealth_client.py tests/test_stealth_curl_transport.py -q
```

Expected: both files pass.

### Task 3: Adaptive 403 and Gateway Rotation

**Files:**
- Modify: `tests/test_stealth_client.py`
- Modify: `core/stealth/stealth_http_client.py`

- [ ] **Step 1: Write failing response-signal tests**

Add tests equivalent to:

```python
def test_403_block_keyword_rotates_family_and_retries(tmp_path):
    transport = Transport([
        Response(403, "Access Denied"),
        Response(200, "ok"),
    ])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )

    result = client.stealth_request(
        "GET",
        "https://fixture/private",
        options={"max_retries": 2},
    )

    assert result["status_code"] == 200
    assert result["timeline"][0]["fingerprint_id"] != (
        result["timeline"][-1]["fingerprint_id"]
    )
    assert client.session_state("https://fixture")[
        "fingerprint_rotations"
    ][-1]["reason"] == "403-block-keyword"


def test_plain_authorization_403_does_not_rotate(tmp_path):
    transport = Transport([Response(403, "permission required")])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    result = client.stealth_request(
        "GET",
        "https://fixture/private",
        options={"max_retries": 2},
    )
    assert result["attempts"] == 1
    assert client.session_state("https://fixture")[
        "fingerprint_rotation_count"
    ] == 0


def test_second_plain_gateway_error_rotates_then_retries(tmp_path):
    transport = Transport([
        Response(502, "gateway"),
        Response(503, "maintenance"),
        Response(200, "ok"),
    ])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    result = client.stealth_request(
        "GET",
        "https://fixture/",
        options={"max_retries": 2, "jitter": False},
    )
    assert result["status_code"] == 200
    assert result["attempts"] == 3
    assert client.session_state("https://fixture")[
        "fingerprint_rotations"
    ][-1]["reason"] == "gateway-502-503-streak"
```

Add controls for a rate-limited 503 and for gateway streak reset after a
non-gateway status.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_stealth_client.py -k "403 or gateway or 503" -q
```

Expected: new adaptive tests fail while existing plain-503/rate-limit tests
remain green.

- [ ] **Step 3: Implement response signal helpers**

Add an ASCII-safe constant:

```python
FINGERPRINT_BLOCK_WORDS = (
    "forbidden",
    "access denied",
    "\u62e6\u622a",
    "\u5b89\u5168\u68c0\u6d4b",
)
```

Add:

```python
def _fingerprint_blocked_403(self, status_code, body):
    text = str(body or "").lower()
    return int(status_code) == 403 and any(
        marker in text for marker in FINGERPRINT_BLOCK_WORDS
    )

def _record_http_fingerprint_signal(self, state, status_code, limited):
    failures = state["fingerprint_failures"]
    failures["timeout"] = 0
    if int(status_code) in {502, 503} and not limited:
        failures["gateway"] += 1
    else:
        failures["gateway"] = 0
    return failures["gateway"]
```

In `stealth_request()`:

1. Track `automatic_rotation_retries = 0`.
2. Record streak values in the response timeline row.
3. On blocking 403, rotate when retry budget and the two-rotation cap permit.
4. Select/advance the existing WAF strategy before retrying the rotated
   fingerprint.
5. On first plain gateway error, retry unchanged.
6. On the second, rotate and retry.
7. Keep rate-limited 503 on the existing rate-limit path.

- [ ] **Step 4: Run tests and verify GREEN**

Run the command from Step 2. Expected: all selected tests pass.

### Task 4: Adaptive Timeout Rotation

**Files:**
- Modify: `tests/test_stealth_client.py`
- Modify: `core/stealth/stealth_http_client.py`

- [ ] **Step 1: Write failing timeout tests**

Add a transport that raises queued exceptions and tests equivalent to:

```python
def test_third_consecutive_timeout_rotates_then_retries(tmp_path):
    transport = ExceptionTransport([
        TimeoutError("one"),
        TimeoutError("two"),
        TimeoutError("three"),
        Response(200, "ok"),
    ])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    result = client.stealth_request(
        "GET",
        "https://fixture/",
        options={"max_retries": 3, "jitter": False},
    )
    assert result["status_code"] == 200
    assert result["attempts"] == 4
    assert client.session_state("https://fixture")[
        "fingerprint_rotations"
    ][-1]["reason"] == "consecutive-timeouts"


def test_http_response_resets_timeout_streak(tmp_path):
    transport = ExceptionTransport([
        TimeoutError("one"),
        TimeoutError("two"),
        Response(200, "ok"),
    ])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    first = client.stealth_request(
        "GET",
        "https://fixture/",
        options={"max_retries": 1, "jitter": False},
    )
    assert first["status"] == "error"
    assert client.session_state("https://fixture")[
        "fingerprint_failures"
    ]["timeout"] == 2

    second = client.stealth_request(
        "GET",
        "https://fixture/",
        options={"max_retries": 0, "jitter": False},
    )
    assert second["status_code"] == 200
    assert client.session_state("https://fixture")[
        "fingerprint_failures"
    ]["timeout"] == 0
```

Also test that a non-timeout exception resets the timeout streak and still uses
the existing generic exception retry path.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_stealth_client.py -k "timeout" -q
```

Expected: failures because timeout classification and streak-triggered rotation
are absent.

- [ ] **Step 3: Implement timeout classification and streak handling**

Implement:

```python
def _is_timeout_exception(self, exc):
    if isinstance(exc, TimeoutError):
        return True
    if exc.__class__.__name__.lower().endswith("timeout"):
        return True
    for module in (native_requests, requests):
        timeout_type = getattr(
            getattr(module, "exceptions", None),
            "Timeout",
            None,
        )
        if timeout_type and isinstance(exc, timeout_type):
            return True
    return False
```

In the exception branch:

- increment `fingerprint_failures["timeout"]` only for timeout exceptions;
- reset it for non-timeout exceptions;
- reset gateway streak for any exception;
- add `failure_class`, `timeout_streak`, and `gateway_streak` to the row;
- on the third timeout, rotate and retry when both budgets permit;
- otherwise retain existing proxy failure accounting and backoff behavior.

- [ ] **Step 4: Run tests and verify GREEN**

Run the command from Step 2, then all of `tests/test_stealth_client.py`.

### Task 5: Fingerprint Health Check

**Files:**
- Modify: `tests/test_stealth_client.py`
- Modify: `core/stealth/stealth_http_client.py`

- [ ] **Step 1: Write failing health tests**

Add tests equivalent to:

```python
def test_health_probe_200_with_target_403_means_fingerprint_blocked(tmp_path):
    transport = Transport([Response(200, "icon")])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    client.session_create("https://fixture", resume=False)

    result = client.check_fingerprint_health(
        "https://fixture",
        target_status_code=403,
    )

    assert result["classification"] == "fingerprint_blocked"
    assert transport.calls[0][1] == "https://fixture/favicon.ico"


@pytest.mark.parametrize("probe_status", [403, 502, 503])
def test_blocked_health_probe_means_ip_or_target_problem(
    tmp_path,
    probe_status,
):
    transport = Transport([Response(probe_status, "blocked")])
    client = StealthHTTPClient(
        state_dir=tmp_path,
        transport_factory=lambda: transport,
        sleep=lambda _: None,
    )
    client.session_create("https://fixture", resume=False)

    result = client.check_fingerprint_health(
        "https://fixture",
        target_status_code=403,
    )

    assert (
        result["classification"]
        == "ip_blocked_or_target_unavailable"
    )
    assert result["probe_status_code"] == probe_status


def test_health_probe_does_not_enter_stealth_request_or_change_counters(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        client,
        "stealth_request",
        lambda *args, **kwargs: pytest.fail("recursive request"),
    )
    before = client.session_state("https://fixture")
    result = client.check_fingerprint_health(
        "https://fixture",
        target_status_code=403,
    )
    after = client.session_state("https://fixture")
    assert result["classification"] == "fingerprint_blocked"
    assert after["rate_limit"] == before["rate_limit"]
    assert after["timeline"] == before["timeline"]
```

Add favicon 404 to root fallback and timeout/unreachable tests.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_stealth_client.py -k "health_probe or fingerprint_health" -q
```

Expected: failures because `check_fingerprint_health()` is missing.

- [ ] **Step 3: Implement the direct probe**

Implement same-origin URL validation, current-proxy reuse, current fingerprint
headers, one direct transport request per candidate URL, and these
classifications:

```python
if probe_status == 200 and target_status == 403:
    classification = "fingerprint_blocked"
elif probe_status in {403, 502, 503}:
    classification = "ip_blocked_or_target_unavailable"
elif probe_status == 200:
    classification = "healthy"
elif error:
    classification = "target_unreachable"
else:
    classification = "inconclusive"
```

Store only `state["fingerprint_health"]`, save state, and do not call WAF,
rate, CAPTCHA, proxy selection, cookie capture, or `_finalize()`.

- [ ] **Step 4: Run tests and verify GREEN**

Run the command from Step 2. Expected: all health tests pass.

### Task 6: Regression, Evidence, and Case State

**Files:**
- Modify if required by the new strict contract:
  `tests/test_stealth_curl_transport.py`
- Create:
  `D:/Open-tgtylab/exports/notes/hunter-stealth-fingerprint-rotation-20260713.md`
- Create:
  `D:/Open-tgtylab/exports/reports/hunter-stealth-fingerprint-rotation-20260713.md`
- Modify:
  `D:/Open-tgtylab/cases/hunter-skill/state.json`

- [ ] **Step 1: Run focused stealth suites**

```powershell
python -m pytest tests/test_stealth_foundation.py tests/test_stealth_client.py tests/test_stealth_curl_transport.py tests/test_stealth_strategy_execution.py tests/test_stealth_mcp.py -q
```

Expected: zero failures.

- [ ] **Step 2: Run syntax and diff checks**

```powershell
python -m py_compile core/stealth/fingerprint_manager.py core/stealth/stealth_http_client.py
git diff --check
```

Expected: exit code zero.

- [ ] **Step 3: Run the full Hunter suite**

```powershell
python -m pytest -q
```

Expected: zero failures. If unrelated pre-existing failures occur, verify and
report them separately rather than changing unrelated modules.

- [ ] **Step 4: Audit requirements against evidence**

Confirm:

- repeated session requests use one `fingerprint_id`;
- process restore preserves it;
- manual and automatic rotations change browser family;
- rotation reasons/counts persist;
- 403, gateway, and timeout thresholds are covered;
- automatic rotation retries never exceed two or escape `max_retries`;
- health probe classifications match the specification;
- no MCP contract changes occurred.

- [ ] **Step 5: Write notes and report**

Record modified files, red-green commands, focused/full test counts, residual
risks, and the dirty-worktree preservation note in both export files.

- [ ] **Step 6: Update case state**

Append a finding named
`stealth_fingerprint_persistence_adaptive_rotation_verified`, update
`updated_at`, add verification fields, and set `next_steps` to any remaining
authorized live-target smoke test. Preserve all existing findings and metadata.
