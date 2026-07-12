# Adaptive HTTP Infrastructure

Hunter exposes a stateful HTTP layer through the single `hunter_tools` MCP server.

## Components

- `core/stealth/fingerprint_manager.py`: coherent browser profiles, session persistence, browser import, freshness pruning.
- `core/stealth/waf_detector.py`: passive fingerprints, bounded active probes, WAF classification, adaptive strategy history.
- `core/stealth/rate_limiter.py`: threshold probes, per-target/per-proxy state, exponential backoff, jitter and long-tail pacing.
- `core/stealth/captcha_handler.py`: captcha classification, injectable OCR engines, bypass checks, and operator handoff artifacts.
- `core/stealth/proxy_pool.py`: classified proxy inventory, injected health checks, target-ban state, scoring and pruning.
- `core/stealth/stealth_http_client.py`: target sessions, cookies, CSRF, redirect-aware requests, audit timelines and request chains.

## MCP tools

```text
hunter_session_create
hunter_session_state
hunter_set_proxy_pool
hunter_stealth_request
hunter_stealth_scan
```

`hunter_stealth_scan` uses bounded probes. Live network execution is separate from unit tests; tests inject transports and never contact public targets.

## Session state

State is stored under `sessions/stealth/` by target hostname and includes the selected fingerprint, cookies, CSRF values, proxy, rate state, steps and request timeline. Operator-required captcha artifacts are saved below `sessions/stealth/captcha/`.

## WAF strategies

Strategies are normalization and transport experiments represented as metadata. The client records outcomes and changes ordering from target history. A deferred or unsuccessful strategy is never reported as a successful bypass.

## Proxy checks

Proxy liveness and target-ban checks require an explicit injected checker or transport. Loading a proxy does not imply it is healthy.

## Operational boundaries

- HTTP/2 multiplexing and WebSocket upgrades are capability-labelled strategies. If the selected transport does not implement them, they are returned as `unsupported` and are not scored as attempts.
- Rate probes default to five timed samples per target rate and report observed RPS. One-sample requests are `inconclusive`.
- Sessions are isolated by scheme, host, and effective port. Response bodies are clipped for MCP output and large bodies are saved under the session response artifact directory.
- Proxy outcomes feed health, score, and per-target ban state; failed proxies rotate on retry.
- Browser version thresholds are supplied by an injectable version source and are refreshed/pruned at startup.
