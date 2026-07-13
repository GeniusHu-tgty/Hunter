# Stealth Fingerprint Persistence and Adaptive Rotation Design

## Goal

Keep one coherent browser fingerprint for the lifetime of each stealth session,
rotate it only through the explicit `rotate_fingerprint()` path, and invoke that
path automatically for narrowly defined blocking signals. Add a side-effect
bounded health check that distinguishes a fingerprint-specific denial from an
IP-level block or an unavailable target.

## Scope

Modify:

- `core/stealth/fingerprint_manager.py`
- `core/stealth/stealth_http_client.py`

Add or revise focused tests under:

- `tests/test_stealth_foundation.py`
- `tests/test_stealth_client.py`
- `tests/test_stealth_curl_transport.py`

Do not add a new MCP tool or change the existing Hunter tool contract.

## Fingerprint Manager

`FingerprintManager.for_session(session_id, ...)` has one responsibility:
return the fingerprint already bound to the session, or choose and bind one
fingerprint when no binding exists. It must never silently replace an existing
binding.

Add:

```python
bind_session(session_id, fingerprint_id)
rotate_fingerprint(
    session_id,
    *,
    current_fingerprint_id=None,
    strategy="random",
    require_impersonate=False,
)
```

`bind_session()` validates the fingerprint ID and restores the in-memory
manager binding from persisted session state.

`rotate_fingerprint()` selects a fingerprint whose `browser` family differs
from the current fingerprint. When `require_impersonate=True`, candidates must
also have a usable curl-cffi `impersonate` value. It updates the manager binding
and returns the selected fingerprint. If no cross-family candidate exists, it
raises a clear `RuntimeError`.

If `for_session()` is called with `require_impersonate=True` for an already
bound fingerprint without impersonation support, it raises a clear error
instead of changing identity.

## Session Lifecycle

New sessions generate `session_id` before selecting a fingerprint. The manager
binding key is the actual `session_id`, not the target origin.

Persisted sessions restore their exact `fingerprint_id` through
`bind_session()`. Transport preparation may backfill a missing `impersonate`
value from that same fingerprint, but must not replace the fingerprint.

New state fields:

```json
{
  "fingerprint_rotation_count": 0,
  "fingerprint_rotations": [],
  "fingerprint_failures": {
    "gateway": 0,
    "timeout": 0
  }
}
```

Legacy session files receive these fields through `setdefault()` during
restore.

## Rotation API

Add a public client method:

```python
rotate_fingerprint(
    target=None,
    *,
    session_id=None,
    reason="manual",
    automatic=False,
)
```

Exactly one of `target` or `session_id` identifies the current runtime.

Add `DetectionSession.rotate_fingerprint(reason="manual")` as a convenience
wrapper around the client method.

Every rotation:

1. Selects a different browser family.
2. Updates `fingerprint_id` and `impersonate`.
3. Increments `fingerprint_rotation_count`.
4. Appends a bounded history event with timestamp, reason, automatic/manual
   mode, previous/new IDs, and previous/new browser families.
5. Appends a request timeline event when rotation occurs inside
   `stealth_request()`.
6. Saves session state immediately.

For the default transport, rotation rebuilds the HTTP session so the TLS
impersonation changes with the browser family, then restores persisted cookies.
Injected zero-argument custom transports keep their existing object for
backward compatibility; their request headers still use the new fingerprint.

## Adaptive Signals

The client maintains persistent per-session streaks and a per-request automatic
rotation retry counter.

### Blocking 403

A 403 triggers rotation only when the lower-cased response body contains at
least one of:

- `forbidden`
- `access denied`
- the Chinese word for interception (`\u62e6\u622a`)
- the Chinese phrase for security inspection (`\u5b89\u5168\u68c0\u6d4b`)

The 403 rotation reason is `403-block-keyword`.

Existing WAF strategy selection still advances on the retry. This preserves the
current WAF adaptation contract while also changing browser identity.

### Gateway 502/503

Only non-rate-limited 502 and 503 responses count toward the gateway streak.

- First consecutive response: retry with the same fingerprint if the existing
  retry budget permits.
- Second consecutive response: rotate with reason
  `gateway-502-503-streak`, then retry.
- Any other HTTP status or a rate-limited 503 resets the gateway streak.

### Consecutive Timeouts

Timeout classification recognizes:

- built-in `TimeoutError`
- native requests timeout exceptions when available
- curl-cffi timeout exceptions when available
- compatible custom timeout exceptions by class name

The first and second consecutive timeouts use the existing exception retry
path. The third consecutive timeout rotates with reason
`consecutive-timeouts`, then retries if budget remains. Any HTTP response or
non-timeout exception resets the timeout streak.

### Retry Bounds

`max_retries` remains the total extra-attempt budget and keeps its existing
range of zero through three.

Automatic fingerprint rotations:

- consume the existing retry budget;
- trigger at most two retries per `stealth_request()` call;
- do not increase the total attempt limit.

If no retry budget remains, the client records the observed streak but does not
rotate to an unverified fingerprint at the end of the call.

## Health Check

Add:

```python
check_fingerprint_health(
    target=None,
    *,
    session_id=None,
    target_status_code=None,
    probe_url=None,
    timeout=5,
)
```

If `target_status_code` is omitted, use the latest main-request status from the
session timeline.

The probe:

- uses the current runtime, fingerprint headers, TLS impersonation, and current
  proxy;
- calls the underlying transport directly;
- performs no retry, WAF strategy selection, rate-limit accounting, CAPTCHA
  handling, recursive health check, or main-request timeline update;
- uses an explicit same-origin `probe_url` when supplied;
- otherwise tries `/favicon.ico`, and falls back to `/` only when the favicon
  response is absent or not a useful health signal such as 404/405.

Classifications:

- probe 200 and target 403: `fingerprint_blocked`
- probe 403, 502, or 503: `ip_blocked_or_target_unavailable`
- probe 200 and target is not 403: `healthy`
- timeout or connection exception: `target_unreachable`
- all other combinations: `inconclusive`

The result includes fingerprint ID/browser, target status, probe URL/status,
elapsed time, transport backend, and a redacted error summary. The latest
result is stored in `state["fingerprint_health"]` and saved without changing
the rate/WAF counters.

## Compatibility

- Preserve existing `stealth_request()` arguments and result fields.
- Preserve zero-argument `transport_factory`.
- Preserve proxy failure retries and proxy rotation.
- Preserve ordinary 503 behavior as non-rate-limited unless existing
  rate-limit signals are present.
- Preserve CAPTCHA, CSRF, cookies, OAuth history, WAF scoring, body truncation,
  and detection-session behavior.
- Do not add or remove MCP tools.

The prior legacy behavior that silently changed an unsupported persisted
fingerprint is intentionally replaced by strict identity persistence because
the new requirement makes explicit rotation the only valid identity change.

## Test Strategy

Use red-green-refactor cycles for:

1. Fixed `for_session()` binding and explicit cross-family rotation.
2. Session creation, repeated requests, and process restore preserving one
   `fingerprint_id`.
3. Manual client and `DetectionSession` rotation state/audit behavior.
4. 403 keyword rotation and a non-keyword 403 control.
5. First gateway retry, second gateway rotation, and streak reset.
6. Rate-limited 503 exclusion.
7. Three timeout rotation and timeout streak reset.
8. Two-rotation cap within the existing retry budget.
9. Default curl transport recreation with cookie preservation.
10. Health classifications and proof that the probe bypasses
    `stealth_request()` side effects.
11. Existing focused stealth suites, then the full Hunter test suite.
