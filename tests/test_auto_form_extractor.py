from core.session.auto_form_extractor import (
    AttackChainFeeder,
    CredentialGenerator,
    FormExtractor,
)


def test_extracts_all_forms_and_selects_cas_login_form():
    html = """
    <form action="/search" method="get">
      <input name="q" placeholder="Search">
    </form>
    <form action="/cas/login" method="post">
      <input name="user" type="text" placeholder="Account">
      <input name="passcode" type="password">
      <input name="execution" type="hidden" value="flow-123">
      <select name="realm">
        <option value="student">Student</option>
        <option value="staff" selected>Staff</option>
      </select>
      <textarea name="note">default note</textarea>
      <button type="submit" name="_eventId" value="submit">Login</button>
    </form>
    """

    forms = FormExtractor().extract_login_forms(
        html,
        "https://example.test/login",
    )

    assert len(forms) == 2
    login = next(item for item in forms if item["is_login"])
    assert login["action"] == "https://example.test/cas/login"
    assert login["method"] == "POST"
    assert login["has_csrf"] is True
    assert login["submit_button"] == {"name": "_eventId", "value": "submit"}
    assert {field["name"] for field in login["fields"]} == {
        "user",
        "passcode",
        "execution",
        "realm",
        "note",
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
        html,
        "https://example.test/",
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


def test_generates_common_and_domain_credentials_with_hidden_defaults():
    form = {
        "action": "https://gnnu.edu.cn/cas/login",
        "method": "POST",
        "fields": [
            {
                "name": "username",
                "type": "text",
                "default_value": "",
                "placeholder": "",
            },
            {
                "name": "password",
                "type": "password",
                "default_value": "",
                "placeholder": "",
            },
            {
                "name": "execution",
                "type": "hidden",
                "default_value": "flow-123",
                "placeholder": "",
            },
        ],
        "has_csrf": True,
        "submit_button": {},
        "is_login": True,
    }

    candidates = CredentialGenerator().generate_credentials(
        form,
        role_hint="admin",
    )

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
    assert all(item["username_field"] == "username" for item in candidates)
    assert all(item["password_field"] == "password" for item in candidates)


def test_marks_captcha_candidates_without_fabricating_a_captcha_value():
    form = {
        "action": "https://example.test/login",
        "method": "POST",
        "fields": [
            {
                "name": "email",
                "type": "email",
                "default_value": "",
                "placeholder": "",
            },
            {
                "name": "password",
                "type": "password",
                "default_value": "",
                "placeholder": "",
            },
            {
                "name": "captcha",
                "type": "text",
                "default_value": "",
                "placeholder": "Captcha",
            },
        ],
        "has_csrf": False,
        "submit_button": {},
        "is_login": True,
    }

    candidates = CredentialGenerator().generate_credentials(form)

    assert candidates
    assert all(item["requires_captcha"] is True for item in candidates)
    assert all(item["captcha_field"] == "captcha" for item in candidates)
    assert all("captcha" not in item["extra_fields"] for item in candidates)


def test_missing_username_or_password_field_returns_no_credentials():
    form = {
        "action": "https://example.test/login",
        "method": "POST",
        "fields": [
            {
                "name": "username",
                "type": "text",
                "default_value": "",
                "placeholder": "",
            }
        ],
        "has_csrf": False,
        "submit_button": {},
        "is_login": True,
    }

    assert CredentialGenerator().generate_credentials(form) == []


def test_feeder_splits_action_and_preserves_first_candidate_compatibility():
    form = {
        "action": "https://example.test/cas/login?service=%2Fadmin",
        "method": "POST",
        "fields": [
            {"name": "user", "type": "text", "default_value": "", "placeholder": ""},
            {"name": "passcode", "type": "password", "default_value": "", "placeholder": ""},
            {
                "name": "execution",
                "type": "hidden",
                "default_value": "flow-123",
                "placeholder": "",
            },
        ],
        "has_csrf": True,
        "submit_button": {"name": "_eventId", "value": "submit"},
        "is_login": True,
    }
    credentials = [
        {
            "username": "admin",
            "password": "admin",
            "username_field": "user",
            "password_field": "passcode",
            "extra_fields": {"execution": "flow-123"},
            "requires_captcha": False,
            "captcha_field": "",
        }
    ]

    result = AttackChainFeeder().feed_chain(
        form,
        credentials,
        {"parameters": {}},
    )

    assert result["target_url"] == "https://example.test"
    assert result["login_path"] == "/cas/login?service=%2Fadmin"
    assert result["username_field"] == "user"
    assert result["password_field"] == "passcode"
    assert result["csrf_field"] == "execution"
    assert result["csrf_token"] == "flow-123"
    assert result["extra_fields"] == {
        "execution": "flow-123",
        "_eventId": "submit",
    }
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


def test_auto_form_classes_are_exported_from_session_package():
    from core.session import (
        AttackChainFeeder as ExportedFeeder,
        CredentialGenerator as ExportedGenerator,
        FormExtractor as ExportedExtractor,
    )

    assert ExportedFeeder is AttackChainFeeder
    assert ExportedGenerator is CredentialGenerator
    assert ExportedExtractor is FormExtractor


def test_feeder_overrides_structured_login_defaults_with_discovery():
    form = {
        "action": "https://example.test/cas/login",
        "method": "POST",
        "fields": [
            {"name": "user", "type": "text", "default_value": "", "placeholder": ""},
            {"name": "passcode", "type": "password", "default_value": "", "placeholder": ""},
            {"name": "execution", "type": "hidden", "default_value": "flow", "placeholder": ""},
        ],
        "has_csrf": True,
        "submit_button": {},
        "is_login": True,
    }
    template = {
        "parameters": {
            "login_path": {"description": "path", "required": False, "default": "/login"},
            "username_field": {"description": "user", "required": False, "default": "username"},
            "password_field": {"description": "pass", "required": False, "default": "password"},
            "csrf_field": {"description": "csrf", "required": False, "default": "csrf_token"},
            "request_method": {"description": "method", "required": False, "default": "POST"},
            "admin_path": {"description": "admin", "required": False, "default": "/admin"},
        }
    }
    credentials = CredentialGenerator().generate_credentials(form)

    result = AttackChainFeeder().feed_chain(form, credentials, template)

    assert result["login_path"] == "/cas/login"
    assert result["username_field"] == "user"
    assert result["password_field"] == "passcode"
    assert result["csrf_field"] == "execution"
    assert result["request_method"] == "POST"
    assert result["admin_path"] == "/admin"

def test_feeder_merges_discovered_and_explicit_extra_fields():
    form = {
        "action": "https://example.test/cas/login",
        "method": "POST",
        "fields": [
            {"name": "user", "type": "text", "default_value": "", "placeholder": ""},
            {"name": "pass", "type": "password", "default_value": "", "placeholder": ""},
            {"name": "execution", "type": "hidden", "default_value": "flow", "placeholder": ""},
        ],
        "has_csrf": True,
        "submit_button": {},
        "is_login": True,
    }
    credentials = [{"username": "admin", "password": "admin"}]

    runtime = AttackChainFeeder().feed_chain(
        form,
        credentials,
        {"extra_fields": {"locale": "zh", "execution": "operator-flow"}},
    )
    structured = AttackChainFeeder().feed_chain(
        form,
        credentials,
        {
            "parameters": {
                "extra_fields": {
                    "description": "extras",
                    "required": False,
                    "default": {"realm": "staff", "execution": "stale"},
                }
            }
        },
    )

    assert runtime["extra_fields"] == {
        "execution": "operator-flow",
        "locale": "zh",
    }
    assert structured["extra_fields"] == {
        "realm": "staff",
        "execution": "flow",
    }

