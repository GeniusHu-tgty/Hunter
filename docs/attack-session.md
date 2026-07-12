# Persistent Attack Sessions

Hunter exposes a bounded multi-step assessment layer on top of the existing
Workflow Kernel and `StealthHTTPClient`.

## Components

- `core/session/attack_session.py`: persistent CookieJar, headers, CSRF/auth
  tokens, extraction state, history, blockers, per-chain execution cursors,
  public redacted views, and full-state checkpoints.
- `core/session/attack_chain.py`: YAML/JSON step loader, substitution,
  preconditions, retries, branching, extraction, and critical-step recovery.
- `core/session/post_exploitation.py`: evidence-gated capability planner.
- `chains/*.yml`: six reusable chain templates.

Attack-session state is stored under `sessions/attack/<session_id>/`. Writes
use atomic replacement and restrictive file permissions. Cookies, configured
headers, CSRF/auth tokens, extracted data, authorization scope, authentication
proof, and chain cursors are authenticated-encrypted with a local Fernet key.
Checkpoints retain the same encrypted full state.

`snapshot()` is the in-process full representation. `persisted_state()` is the
encrypted disk representation. `public_snapshot()` is the external
representation: cookie values, configured header values, CSRF tokens, auth
tokens, and sensitive history/extracted fields are replaced with
`[REDACTED]`. MCP state responses use the public representation.

## MCP Flow

```text
hunter_session_start(target_url, authorization)
-> hunter_session_execute_chain(session_id, chain_name, params)
-> hunter_session_state(session_id=...)
-> hunter_session_checkpoint(session_id, save|restore|list, name)
-> hunter_post_exploit(session_id, vuln_type, vuln_details, approved)
```

`hunter_session_state` remains backward compatible:

- `target=...` returns the existing adaptive HTTP/Stealth session.
- `session_id=...` returns the persistent AttackSession.
- Providing both is rejected.

## Chain Schema

Each chain has a `name`, optional parameters, a start step, and a list of
steps. Supported actions are:

- `request`
- `extract`
- `condition`
- `exploit`
- `wait`

References are validated at load time. Execution has a step budget, retry
limits, payload variants, retry-strategy metadata, and bounded waits. A failed
critical step creates a checkpoint containing the blocker before returning.
Each chain persists its current step after every transition. Restoring a
checkpoint resumes at the failed or pending step and does not replay already
successful request or exploit side effects.

Every AttackSession owns a separate `StealthHTTPClient` state directory and
transport. Requests must remain inside `authorization.allowed_origins` and use
an explicitly allowed method. The default scope permits only the target origin
and `GET`, `HEAD`, and `OPTIONS`; state-changing methods require operator scope
at session creation.

## Safety Boundary

Post-exploitation requires confirmed evidence IDs that match the session
authorization, an approval ID and approving operator, authorized capabilities,
and per-action approval. High-impact actions such as
server-side script upload, command execution, reverse-shell establishment,
Redis persistence, and cloud metadata access are never executed directly by
the planner. The planner emits auditable action descriptors; a separate
authorized backend must receive explicit per-action approval.

Session authorization is request scope, not a trusted approval registry. The
default MCP planner therefore never promotes caller-supplied approval fields to
`ready`. A host must inject an independent `approval_verifier` backed by its
operator/evidence registry; without that verifier, requested actions remain
`approval-required`.

Planning and approval states are not execution success. In particular,
`approval-required`, `ready`, `deferred`, `rejected`, and `blocked` never take
an exploit step's success branch. The chain pauses on that step, returns the
planning status plus `pending.step_id`, and retains the cursor for a later
authorized retry.

## Preset Templates

- `login_to_admin.yml`
- `sqli_to_data_dump.yml`
- `file_upload_to_shell.yml`
- `ssrf_to_internal_access.yml`
- `jwt_to_account_takeover.yml`
- `card_shop_attack.yml`

Templates contain placeholders and proof steps. Operators must provide
authorized target-specific parameters and review the chain before execution.
