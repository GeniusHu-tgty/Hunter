# Automatic Login Form Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic HTML login-form extraction, bounded credential generation, attack-chain parameter feeding, and opt-in-compatible automatic preparation in `hunter_session_execute_chain`.

**Architecture:** Keep parsing and candidate generation in a new standard-library module. Keep chain execution state and authorization in the existing session/chain layers. The MCP integration performs one authorized GET, merges only missing login parameters, and executes one first credential while returning the full candidate list as redacted preparation metadata.

**Tech Stack:** Python 3.14, `html.parser.HTMLParser`, `urllib.parse`, PyYAML, pytest, existing `AttackSession` and `StealthHTTPClient`.

---

### Task 1: Add red tests for the standalone extractor

**Files:**
- Create: `tests/test_auto_form_extractor.py`
- Create: `core/session/auto_form_extractor.py`

- [ ] **Step 1: Write failing parser tests**

Add tests with these exact behaviors:

```python
def test_extracts_all_forms_and_selects_cas_login_form():
    html = """
    <form action="/search" method="get">
      <input name="q" placeholder="Search">
    </form>
    <form action="/cas/login" method="post">
      <input name="user" type="text" placeholder="Account">
      <input name="passcode" type="password">
      <input name="execution" type="hidden" value="flow-123">
      <select name="realm"><option value="staff" selected>Staff</option></select>
      <textarea name="note">default note</textarea>
      <button type="submit" name="_eventId" value="submit">Login</button>
    </form>
    """

    forms = FormExtractor().extract_login_forms(
        html, "https://example.test/login"
    )

    assert len(forms) == 2
    login = next(item for item in forms if item["is_login"])
    assert login["action"] == "https://example.test/cas/login"
    assert login["method"] == "POST"
    assert login["has_csrf"] is True
    assert login["submit_button"] == {"name": "_eventId", "value": "submit"}
    assert {field["name"] for field in login["fields"]} == {
        "user", "passcode", "execution", "realm", "note",
    }
    assert next(
        field for field in login["fields"] if field["name"] == "realm"
    )["default_value"] == "staff"
    assert next(
        field for field in login["fields"] if field["name"] == "note"
    )["default_value"] == "default note"


def test_login_priority_prefers_action_then_password_then_identity_field():
    html = """
    <form action="/signin"><input name="q"></form>
    <form action="/profile"><input type="password" name="secret"></form>
    <form action="/contact"><input name="email"></form>
    """

    forms = FormExtractor().extract_login_forms(
        html, "https://example.test/"
    )

    assert forms[0]["is_login"] is True
    assert forms[1]["is_login"] is False
    assert forms[2]["is_login"] is False


def test_forms_without_login_signals_are_not_selected():
    forms = FormExtractor().extract_login_forms(
        '<form action="/search"><input name="q"></form>',
        "https://example.test/",
    )

    assert forms[0]["is_login"] is False


def test_missing_action_and_invalid_method_are_normalized():
    forms = FormExtractor().extract_login_forms(
        '<form method="patch"><input name="username"></form>',
        "https://example.test/account/login",
    )

    assert forms[0]["action"] == "https://example.test/account/login"
    assert forms[0]["method"] == "GET"
```

- [ ] **Step 2: Run the focused tests and verify the expected red failure**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_auto_form_extractor.py -q
```

Expected: collection fails because `core.session.auto_form_extractor` does not
exist yet.

- [ ] **Step 3: Implement the minimal parser**

Implement `_FormParser` with explicit form stack state. Store controls only
inside the active form. Normalize attributes case-insensitively, preserve
empty values, and close dangling forms at EOF. Build field records with
`name`, `type`, `default_value`, and `placeholder`. For select controls use
the selected option, otherwise the first option; for textarea use collected
text. Record the first submit input/button with its `name` and `value`.

Score forms with action keywords at the highest priority, password fields next,
and identity field names last. Select the first positive-scoring form on ties
and set `is_login` on every returned form. When all scores are zero, mark every
form as non-login. Use `urljoin(base_url, action or base_url)` and normalize
methods to GET or POST.

- [ ] **Step 4: Run the focused tests and verify green**

Run the same pytest command. Expected: all parser tests pass.

- [ ] **Step 5: Run a syntax check**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m py_compile core/session/auto_form_extractor.py
```

Expected: exit code 0.

### Task 2: Add red tests and implementation for credential generation

**Files:**
- Modify: `tests/test_auto_form_extractor.py`
- Modify: `core/session/auto_form_extractor.py`

- [ ] **Step 1: Write failing credential tests**

Add:

```python
def test_generates_common_and_domain_credentials_with_hidden_defaults():
    form = {
        "action": "https://gnnu.edu.cn/cas/login",
        "method": "POST",
        "fields": [
            {"name": "username", "type": "text", "default_value": "", "placeholder": ""},
            {"name": "password", "type": "password", "default_value": "", "placeholder": ""},
            {"name": "execution", "type": "hidden", "default_value": "flow-123", "placeholder": ""},
        ],
        "has_csrf": True,
        "submit_button": {},
        "is_login": True,
    }

    candidates = CredentialGenerator().generate_credentials(form, role_hint="admin")

    pairs = {(item["username"], item["password"]) for item in candidates}
    assert len(candidates) >= 20
    assert ("admin", "admin") in pairs
    assert ("admin", "123456") in pairs
    assert ("admin", "gnnu@123") in pairs
    assert ("admin", "gnnu2024") in pairs
    assert all(
        item["extra_fields"] == {"execution": "flow-123"}
        for item in candidates
    )


def test_marks_captcha_candidates_without_fabricating_a_captcha_value():
    form = {
        "action": "https://example.test/login",
        "method": "POST",
        "fields": [
            {"name": "email", "type": "email", "default_value": "", "placeholder": ""},
            {"name": "password", "type": "password", "default_value": "", "placeholder": ""},
            {"name": "captcha", "type": "text", "default_value": "", "placeholder": "Captcha"},
        ],
        "has_csrf": False,
        "submit_button": {},
        "is_login": True,
    }

    candidates = CredentialGenerator().generate_credentials(form)

    assert candidates
    assert all(item["requires_captcha"] is True for item in candidates)
    assert all("captcha" not in item["extra_fields"] for item in candidates)
```

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_auto_form_extractor.py -q
```

Expected: the new tests fail because `CredentialGenerator` is not implemented.

- [ ] **Step 3: Implement the minimal credential generator**

Use ordered, duplicate-free baseline pairs containing:

```text
admin/admin
admin/123456
admin/password
admin/admin123
test/test
root/root
guest/guest
user/user
admin/password123
admin/letmein
admin/welcome1
root/toor
root/123456
test/123456
guest/123456
user/123456
wiener/peter
admin/qwerty
admin/qwerty123
admin/2024!
admin/admin2024
```

Derive a safe organization token from the action hostname, removing `www`
and common public suffix labels. Add 3-5 variants such as `<token>@123`,
`<token>2024`, `<token>123`, `<token>!`, and `<token>admin`; include role-hint
variants when a role hint is supplied. Detect username fields by name and
type, password fields by type or name, and captcha fields by name/type/
placeholder. Copy only hidden named fields into each candidate's
`extra_fields`. Set `requires_captcha` and `captcha_field` when applicable.

- [ ] **Step 4: Run focused tests and verify green**

Run the same pytest command. Expected: parser and credential tests pass.

### Task 3: Add red tests and implementation for attack-chain feeding

**Files:**
- Modify: `tests/test_auto_form_extractor.py`
- Modify: `core/session/auto_form_extractor.py`
- Modify: `core/session/__init__.py`

- [ ] **Step 1: Write failing feeder tests**

Add:

```python
def test_feeder_splits_action_and_preserves_first_candidate_compatibility():
    form = {
        "action": "https://example.test/cas/login?service=%2Fadmin",
        "method": "POST",
        "fields": [
            {"name": "user", "type": "text", "default_value": "", "placeholder": ""},
            {"name": "passcode", "type": "password", "default_value": "", "placeholder": ""},
            {"name": "execution", "type": "hidden", "default_value": "flow-123", "placeholder": ""},
        ],
        "has_csrf": True,
        "submit_button": {},
        "is_login": True,
    }
    credentials = [
        {
            "username": "admin",
            "password": "admin",
            "extra_fields": {"execution": "flow-123"},
            "requires_captcha": False,
        }
    ]

    result = AttackChainFeeder().feed_chain(form, credentials, {"parameters": {}})

    assert result["target_url"] == "https://example.test"
    assert result["login_path"] == "/cas/login?service=%2Fadmin"
    assert result["username_field"] == "user"
    assert result["password_field"] == "passcode"
    assert result["extra_fields"] == {"execution": "flow-123"}
    assert result["username"] == "admin"
    assert result["password"] == "admin"
    assert result["credentials"] == credentials


def test_feeder_does_not_replace_explicit_nonempty_parameters():
    form = {
        "action": "https://example.test/login",
        "method": "POST",
        "fields": [
            {"name": "user", "type": "text", "default_value": "", "placeholder": ""},
            {"name": "pass", "type": "password", "default_value": "", "placeholder": ""},
        ],
        "has_csrf": False,
        "submit_button": {},
        "is_login": True,
    }
    result = AttackChainFeeder().feed_chain(
        form,
        [{"username": "generated", "password": "generated"}],
        {
            "target_url": "https://operator.test",
            "username_field": "account",
            "username": "operator",
            "password": "secret",
        },
    )

    assert result["target_url"] == "https://operator.test"
    assert result["username_field"] == "account"
    assert result["username"] == "operator"
    assert result["password"] == "secret"
```

- [ ] **Step 2: Run focused tests and verify red**

Run the focused test file. Expected: the feeder tests fail because
`AttackChainFeeder` is not implemented.

- [ ] **Step 3: Implement feeder and exports**

Normalize either a chain parameter dictionary or a chain definition with a
`parameters` mapping. Start from explicit values, fill only missing or blank
values, then add the required output keys. Split action URLs with
`urlparse`: `target_url` is scheme plus netloc and `login_path` is path plus
query. Use the first candidate for scalar compatibility fields. Select the
first token-like hidden field as `csrf_field`/`csrf_token`; keep every hidden
field in `extra_fields`. Export all three classes from `core.session`.

- [ ] **Step 4: Run focused tests and verify green**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_auto_form_extractor.py -q
```

Expected: all standalone extractor, generator, and feeder tests pass.

### Task 4: Support hidden-field merging in the existing chain

**Files:**
- Modify: `tests/test_chain_parameters.py`
- Modify: `core/session/attack_chain.py`
- Modify: `chains/login_to_admin.yml`

- [ ] **Step 1: Write the failing merge regression test**

Add a request definition that contains:

```python
"data": {
    "${username_field}": "${username}",
    "${password_field}": "${password}",
    "${csrf_field}": "${csrf_token}",
},
"extra_fields": "${extra_fields}",
```

Execute it with `extra_fields={"execution": "flow-123", "lt": "lt-456"}` and
assert the POST data contains both hidden fields plus the selected username
and password. Also assert a colliding `username` hidden value is overwritten
by the explicit username.

- [ ] **Step 2: Run the regression test and verify red**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_chain_parameters.py -k extra_fields -q
```

Expected: the request executor receives an unrecognized `extra_fields` request
member or the hidden fields are absent.

- [ ] **Step 3: Implement additive merge behavior**

In `_execute_request`, pop `extra_fields` after substitution. Require a
mapping when present, copy its non-empty keys into the form data, then update
with the explicit `data` mapping so username/password/CSRF keys are
authoritative. Keep the existing session CSRF fallback for forms that do not
provide explicit CSRF data.

Add `extra_fields` as a non-required parameter to the submit step of
`chains/login_to_admin.yml`. Do not change the six-template parameter
validation contract beyond this additive optional value.

- [ ] **Step 4: Run focused chain tests and verify green**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_chain_parameters.py -q
```

Expected: all chain parameter tests pass, including the new merge regression.

### Task 5: Add red MCP integration tests

**Files:**
- Modify: `tests/test_chain_parameters.py`
- Modify: `mcp_server.py`

- [ ] **Step 1: Write failing MCP tests**

Add tests that:

1. inspect `hunter_session_execute_chain` and assert `auto_extract` exists,
   defaults to `True`, and the original first three parameters remain in the
   same order;
2. monkeypatch `_attack_request_executor` to return a login HTML page for the
   auto-discovery GET and a successful admin response for the chain's
   subsequent requests;
3. call the MCP function with `params={"target_url": "https://example.test"}`
   and `auto_extract=True`, then assert the auto-generated username field,
   password field, login path, hidden execution value, and first credential
   are reflected in the chain request;
4. call it without `target_url` and assert the existing required-parameter
   error is returned without an auto-discovery request;
5. return HTML without a login form and assert the legacy chain result/error is
   preserved.

- [ ] **Step 2: Run the new MCP tests and verify red**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_chain_parameters.py -k auto_extract -q
```

Expected: signature and integration assertions fail because no `auto_extract`
parameter or preparation path exists.

- [ ] **Step 3: Implement bounded automatic preparation**

Change the MCP signature to:

```python
async def hunter_session_execute_chain(
    session_id: str,
    chain_name: str,
    params: Optional[Dict[str, Any]] = None,
    auto_extract: bool = True,
) -> str:
```

Inside the existing `run_chain` closure:

1. load the chain;
2. copy caller params;
3. detect login-capable chains from the placeholders in their steps;
4. if `auto_extract` is true and `target_url` is non-empty, derive the
   discovery URL: preserve an existing non-root target path, otherwise join
   the explicit/default `login_path` to the target origin;
5. GET the discovery URL through `_attack_request_executor`;
6. parse the response body with `FormExtractor`;
7. select the marked login form, generate candidates, and call
   `AttackChainFeeder`;
8. merge only blank/missing caller values;
9. execute the chain once with the first candidate;
10. attach a redacted preparation summary to the result.

If the auto-discovery GET fails or no login form is found, do not synthesize
credentials; execute the legacy chain with the original parameters. Keep
existing exception envelopes and session checkpoint behavior intact. Store
only field names, action/method, `has_csrf`, captcha status, and candidate
count in the public summary.

- [ ] **Step 4: Run the MCP tests and verify green**

Run the focused `auto_extract` selection. Expected: all new tests pass.

### Task 6: Run regression verification and inspect the diff

**Files:**
- Modify: `tests/test_session.py` only if an existing session regression needs
  a focused assertion for the redacted auto-extract summary.

- [ ] **Step 1: Run all focused suites**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest tests/test_auto_form_extractor.py tests/test_chain_parameters.py tests/test_session.py -q
```

Expected: zero failures.

- [ ] **Step 2: Run Python compilation**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m py_compile `
    core/session/auto_form_extractor.py `
    core/session/attack_chain.py `
    mcp_server.py
```

Expected: exit code 0.

- [ ] **Step 3: Run the complete Hunter suite**

Run:

```powershell
& 'C:\Program Files\Python314\python.exe' -m pytest -q
```

Expected: all tests pass. If an unrelated pre-existing failure appears,
record its exact test name and output in the evidence note rather than
changing unrelated files.

- [ ] **Step 4: Inspect scoped diff and ensure no unrelated edits were reverted**

Run:

```powershell
git diff --check
git status --short
git diff -- core/session/auto_form_extractor.py core/session/__init__.py core/session/attack_chain.py chains/login_to_admin.yml mcp_server.py tests/test_auto_form_extractor.py tests/test_chain_parameters.py
```

Confirm that existing dirty work in other files remains present and that
secret values from fixtures are not emitted in report or note files.

### Task 7: Persist case evidence and update state

**Files:**
- Create: `D:\Open-tgtylab\exports\notes\hunter-auto-form-extraction-20260713.md`
- Create: `D:\Open-tgtylab\exports\reports\hunter-auto-form-extraction-20260713.md`
- Modify: `D:\Open-tgtylab\cases\hunter-skill\state.json` through `hunter_case_update`

- [ ] **Step 1: Write a redacted verification note**

Record the implementation paths, test commands, pass counts, parser behavior,
single-candidate safety policy, and any residual risk. Do not include actual
passwords, CSRF values, cookies, or target secrets.

- [ ] **Step 2: Write the concise report**

Summarize the delivered classes, MCP integration, compatibility behavior,
tests, and residual limitation that JavaScript-rendered forms require the
browser bridge.

- [ ] **Step 3: Update case state**

Merge a new finding with:

```json
{
  "type": "automatic_login_form_extraction_verified",
  "severity": "done",
  "evidence": "Focused extractor, chain, session, compilation, and full-suite verification results recorded in exports/notes/hunter-auto-form-extraction-20260713.md.",
  "files": [
    "C:\\Users\\Administrator\\.agents\\skills\\hunter\\core\\session\\auto_form_extractor.py",
    "C:\\Users\\Administrator\\.agents\\skills\\hunter\\mcp_server.py",
    "C:\\Users\\Administrator\\.agents\\skills\\hunter\\core\\session\\attack_chain.py"
  ]
}
```

Set `next_steps` to the next authorized validation action: explicitly
exercise the new extractor against a permitted fixture and review the
returned credential candidates before any repeated login attempts.
