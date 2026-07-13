# Automatic Login Form Extraction Design

**Date:** 2026-07-13

## Goal

Add a standard-library-only module that discovers login form structure from
HTML, generates bounded authorized credential candidates, and feeds the
discovered values into the existing attack-chain parameter model without
changing the default single-credential execution semantics.

## Scope

This change covers:

- `core/session/auto_form_extractor.py`
  - `FormExtractor`
  - `CredentialGenerator`
  - `AttackChainFeeder`
- `hunter_session_execute_chain(..., auto_extract=True)`
- the login chain's request data merge for arbitrary hidden fields
- focused unit and integration tests
- case notes and report evidence

It does not add credential iteration, browser automation, CAPTCHA solving, or
new attack-chain templates. A generated credential list is returned for an
operator-controlled later action; automatic execution uses only the first
candidate.

## Architecture

### FormExtractor

`FormExtractor` subclasses `html.parser.HTMLParser`. It records every `form`
and every descendant `input`, `select`, and `textarea` without requiring
BeautifulSoup or another dependency.

Each returned form contains:

```python
{
    "action": "https://target.test/cas/login",
    "method": "POST",
    "fields": [
        {
            "name": "username",
            "type": "text",
            "default_value": "",
            "placeholder": "",
        }
    ],
    "has_csrf": True,
    "submit_button": {"name": "_eventId", "value": "submit"},
    "is_login": True,
}
```

All forms are returned. Exactly one form is selected as the login form when
at least one form exists, using the following score ordering:

1. action contains `login`, `signin`, `auth`, `logon`, `sso`, or `cas`;
2. the form contains a password input;
3. the form contains an input whose name contains `user`, `account`, `email`,
   or `phone`.

The implementation preserves document order as a tie breaker. The selected
form is marked with `is_login=True`; non-selected forms are marked false.
Missing form actions resolve to the supplied `base_url`. Relative actions are
resolved with `urljoin`. The method is upper-cased and constrained to GET or
POST, defaulting to GET for invalid or absent values.

Hidden fields whose names indicate CSRF or authentication flow state are
treated as token fields. The detection includes `csrf`, `xsrf`, `token`,
`_token`, `authenticity_token`, `execution`, and `lt`. Their values remain in
the field list and are also available through the feeder's `extra_fields`.
This captures CAS forms while avoiding a dependency on a specific framework.

### CredentialGenerator

`CredentialGenerator.generate_credentials` identifies the username and
password field names from the selected form and returns dictionaries shaped
as follows:

```python
{
    "username": "admin",
    "password": "admin",
    "extra_fields": {"execution": "opaque-value"},
    "requires_captcha": False,
}
```

The baseline list contains at least 20 deterministic username/password pairs,
including the required common combinations. Domain-derived candidates are
generated from the form action hostname and `role_hint`, with common
organization, year, and punctuation variants. Duplicate pairs are removed
while preserving order.

Captcha fields are detected by field name, input type, or placeholder. They
are not populated with guessed values. Instead, each generated candidate is
marked with `requires_captcha=True` and the captcha field name is recorded.
Hidden defaults are copied into every candidate's `extra_fields`.

### AttackChainFeeder

`feed_chain` accepts the extracted login form, generated credentials, and a
chain template or parameter dictionary. It returns an execution-ready
parameter dictionary containing:

```python
{
    "target_url": "https://target.test",
    "login_path": "/cas/login",
    "username_field": "username",
    "password_field": "password",
    "csrf_field": "execution",
    "csrf_token": "opaque-value",
    "extra_fields": {"execution": "opaque-value"},
    "credentials": [...],
    "username": "admin",
    "password": "admin",
}
```

`username` and `password` are the first candidate only. Existing explicit
non-empty parameters remain authoritative. `target_url` is normalized to the
action origin and `login_path` contains the action path plus query string.
The feeder never silently broadens authorization scope; the existing
`AttackSession.authorize_request` check remains the final origin/method gate.

The login template gets an additive `extra_fields` parameter on the submit
request. `AttackChain._execute_request` merges that mapping into form data
before automatic CSRF fallback. Explicit username/password fields overwrite
colliding hidden values, so a malicious page cannot replace the selected
credential fields through a same-name hidden input.

### MCP integration

The signature becomes:

```python
async def hunter_session_execute_chain(
    session_id: str,
    chain_name: str,
    params: Optional[Dict[str, Any]] = None,
    auto_extract: bool = True,
) -> str:
```

The existing positional arguments remain valid. Before chain execution,
automatic extraction runs only when all of the following are true:

- `auto_extract` is true;
- the loaded chain exposes `username_field` and `password_field` placeholders;
- a non-empty `target_url` is present in caller parameters.

This preserves the existing required-parameter error for calls that omit
`target_url`. The page is fetched through `_attack_request_executor` using the
existing stateful stealth HTTP client and session authorization. The response
body is passed to `FormExtractor`; credentials are generated; the feeder
merges only missing or blank runtime values. If no login form is found, the
legacy chain execution path runs unchanged and returns its normal validation
result.

The returned `data` contains the chain result and a redacted
`auto_extract` summary with form metadata and candidate count. Candidate
passwords and token values are never written to notes, reports, or MCP
evidence.

## Error handling and safety

- Empty or malformed HTML returns an empty form list.
- Invalid base URLs raise `ValueError` from the extractor.
- Forms without named controls remain representable but cannot become a
  login form unless they contain a recognized submit/action signal.
- Missing username or password fields yield an empty credential list and do
  not cause a fabricated login request.
- CAPTCHA forms are reported as requiring operator handling.
- Cross-origin form actions are preserved in the extracted data but execution
  is rejected by the existing session origin policy unless explicitly
  authorized.
- Auto extraction never loops over credentials and never bypasses approval,
  method, origin, or checkpoint rules.

## Testing

Add focused tests for:

1. relative action resolution, method normalization, all control types, default
   values, placeholders, and submit button extraction;
2. login-form priority and CAS/CSRF token detection;
3. at least 20 baseline credential pairs, domain-derived candidates,
   duplicate removal, hidden-field retention, and CAPTCHA marking;
4. feeder output, action origin/path splitting, explicit-parameter precedence,
   and the first-candidate compatibility scalars;
5. hidden-field merging in `AttackChain`;
6. MCP signature compatibility, auto-fetch with a stubbed executor, no-form
   fallback, and the existing missing-`target_url` validation behavior;
7. the complete existing Hunter test suite and Python compilation.

## Alternatives considered

### Third-party DOM parser

BeautifulSoup or lxml would reduce parser code, but neither is a declared
runtime dependency. Adding one for a bounded form extraction task would
increase installation and supply-chain surface.

### Credential iteration inside the chain engine

Looping over all candidates would automate more work, but it changes a
single-step chain into an unbounded authentication campaign and may trigger
account lockout. It is intentionally deferred behind an explicit operator
action.

### Browser-only extraction

Browser DOM extraction would handle JavaScript-rendered forms, but it would
make a deterministic HTML utility depend on the Playwright bridge and would
not solve ordinary server-rendered login pages. The standard-library parser is
the default; browser extraction remains a future fallback.
