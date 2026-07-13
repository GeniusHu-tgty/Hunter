import asyncio
import json
import inspect
from pathlib import Path

import pytest
import yaml

import mcp_server
from core.session import AttackChain, AttackSession


CHAIN_NAMES = [
    "login_to_admin.yml",
    "sqli_to_data_dump.yml",
    "file_upload_to_shell.yml",
    "ssrf_to_internal_access.yml",
    "jwt_to_account_takeover.yml",
    "card_shop_attack.yml",
]


def parameter(description, required=False, default=""):
    return {
        "description": description,
        "required": required,
        "default": default,
    }


def test_parameter_descriptors_use_defaults_and_report_missing_required(tmp_path):
    chain=AttackChain(
        {
            "name":"parameter-validation",
            "parameters":{
                "target_url":parameter("目标根URL",required=True),
                "path":parameter("请求路径",default="/login"),
            },
            "steps":[
                {
                    "step_id":"visit",
                    "name":"Visit",
                    "action":"request",
                    "request":{
                        "method":"GET",
                        "url":"${target_url}${path}",
                    },
                }
            ],
        },
        request_executor=lambda session,request:{
            "status":"ok",
            "status_code":200,
            "url":request["url"],
            "headers":{},
            "body":"ok",
        },
    )
    session=AttackSession("https://example.test",storage_dir=tmp_path)

    with pytest.raises(
        ValueError,
        match=r"缺少必要参数: target_url \(目标根URL\)",
    ):
        chain.execute(session)

    result=chain.execute(session,params={"target_url":"https://example.test"})
    assert result["status"]=="complete"
    assert chain.parameters=={"target_url":"","path":"/login"}
    assert chain.parameter_definitions["target_url"]["required"] is True


def test_substitution_supports_dynamic_field_names_and_empty_cookie_fallback(tmp_path):
    seen=[]
    chain=AttackChain(
        {
            "name":"dynamic-fields",
            "parameters":{
                "target_url":parameter("目标根URL",required=True),
                "session_cookie":parameter("会话Cookie"),
                "username_field":parameter("用户名字段",default="username"),
                "username":parameter("用户名",required=True),
            },
            "steps":[
                {
                    "step_id":"submit",
                    "name":"Submit",
                    "action":"request",
                    "request":{
                        "method":"POST",
                        "url":"${target_url}/login",
                        "headers":{"Cookie":"${session_cookie}"},
                        "data":{"${username_field}":"${username}"},
                    },
                }
            ],
        },
        request_executor=lambda session,request:seen.append(request) or {
            "status":"ok",
            "status_code":200,
            "url":request["url"],
            "headers":{},
            "body":"ok",
        },
    )
    session=AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id":"parameter-test",
            "approved_by":"operator",
            "allowed_methods":["POST"],
        },
    )
    session.update_cookies({"JSESSIONID":"from-session"})

    result=chain.execute(
        session,
        params={
            "target_url":"https://example.test",
            "username":"admin",
        },
    )

    assert result["status"]=="complete"
    assert seen[0]["url"]=="https://example.test/login"
    assert seen[0]["data"]=={"username":"admin"}
    assert seen[0]["headers"]["Cookie"]=="JSESSIONID=from-session"


def test_legacy_scalar_parameter_definitions_remain_compatible(tmp_path):
    seen=[]
    chain=AttackChain(
        {
            "name":"legacy-parameters",
            "parameters":{"path":"/legacy"},
            "steps":[
                {
                    "step_id":"visit",
                    "name":"Visit",
                    "action":"request",
                    "request":{"method":"GET","path":"${path}"},
                }
            ],
        },
        request_executor=lambda session,request:seen.append(request) or {
            "status":"ok",
            "status_code":200,
            "url":request["url"],
            "headers":{},
            "body":"ok",
        },
    )
    result=chain.execute(
        AttackSession("https://example.test",storage_dir=tmp_path)
    )
    assert result["status"]=="complete"
    assert seen[0]["url"]=="https://example.test/legacy"


@pytest.mark.parametrize("name",CHAIN_NAMES)
def test_preset_templates_declare_structured_runtime_parameters(name,tmp_path):
    path=Path(mcp_server.HUNTER_DIR)/"chains"/name
    text=path.read_text(encoding="utf-8-sig")
    definition=yaml.safe_load(text)
    parameters=definition["parameters"]

    assert "# 用途:" in text
    assert "# 前置条件:" in text
    assert "# 期望结果:" in text
    assert parameters["target_url"]==parameter("目标根URL",required=True)
    assert all(
        isinstance(value,dict)
        and {"description","required","default"}<=set(value)
        for value in parameters.values()
    )
    assert "example.com" not in text
    assert "abc123" not in text

    chain=AttackChain.load(path)
    assert chain.undefined_variables==set()
    session=AttackSession("https://example.test",storage_dir=tmp_path/name)
    with pytest.raises(ValueError,match="缺少必要参数: target_url"):
        chain.execute(session)


def test_session_execute_chain_returns_parameter_validation_error(tmp_path):
    store=mcp_server._reset_attack_session_store(tmp_path/"sessions")
    session=store.create(
        "https://example.test",
        authorization={
            "approval_id":"parameter-test",
            "approved_by":"operator",
            "allowed_methods":["GET","POST"],
        },
    )
    result=json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"username":"admin","password":"test123"},
        )
    ))
    assert result["status"]=="error"
    assert result["error"]=="缺少必要参数: target_url (目标根URL)"


def test_login_template_substitutes_runtime_form_and_session_values(tmp_path):
    seen=[]

    def request_executor(session,request):
        seen.append(request)
        if request["url"].endswith("/login") and request["method"]=="GET":
            body='<input name="csrf_token" value="token-123">'
        elif request["url"].endswith("/admin"):
            body='<h1>Admin dashboard</h1><a href="/admin/users">Manage</a>'
        else:
            body="login accepted"
        return {
            "status":"ok",
            "status_code":200,
            "url":request["url"],
            "headers":{},
            "body":body,
        }

    session=AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id":"login-template",
            "approved_by":"operator",
            "allowed_methods":["GET","POST"],
        },
    )
    chain=AttackChain.load(
        Path(mcp_server.HUNTER_DIR)/"chains"/"login_to_admin.yml",
        request_executor=request_executor,
    )
    result=chain.execute(
        session,
        params={
            "target_url":"https://example.test",
            "session_cookie":"JSESSIONID=runtime",
            "username":"admin",
            "password":"test123",
            "username_field":"user",
            "password_field":"pass",
            "csrf_field":"_token",
            "extra_fields":{"execution":"flow-123"},
        },
    )

    assert result["status"]=="complete"
    assert [item["url"] for item in seen]==[
        "https://example.test/login",
        "https://example.test/login",
        "https://example.test/admin",
    ]
    assert seen[1]["data"]=={
        "user":"admin",
        "pass":"test123",
        "_token":"token-123",
        "execution":"flow-123",
    }
    assert all(
        item["headers"]["Cookie"]=="JSESSIONID=runtime"
        for item in seen
    )
    assert session.authentication["verified"] is True


def test_request_merges_extra_fields_without_overriding_explicit_data(tmp_path):
    seen = []
    chain = AttackChain(
        {
            "name": "extra-fields",
            "parameters": {
                "target_url": parameter("target", required=True),
                "username_field": parameter("user field", default="username"),
                "password_field": parameter("password field", default="password"),
                "username": parameter("username", required=True),
                "password": parameter("password", required=True),
                "extra_fields": parameter("extra fields", default={}),
            },
            "steps": [
                {
                    "step_id": "submit",
                    "name": "Submit",
                    "action": "request",
                    "request": {
                        "method": "POST",
                        "url": "${target_url}/cas/login",
                        "extra_fields": "${extra_fields}",
                        "data": {
                            "${username_field}": "${username}",
                            "${password_field}": "${password}",
                        },
                    },
                }
            ],
        },
        request_executor=lambda session, request: seen.append(request) or {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": "ok",
        },
    )
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "extra-fields",
            "approved_by": "operator",
            "allowed_methods": ["POST"],
        },
    )

    result = chain.execute(
        session,
        params={
            "target_url": "https://example.test",
            "username": "admin",
            "password": "secret",
            "extra_fields": {
                "username": "hidden-user",
                "execution": "flow-123",
                "lt": "lt-456",
            },
        },
    )

    assert result["status"] == "complete"
    assert seen[0]["data"] == {
        "username": "admin",
        "execution": "flow-123",
        "lt": "lt-456",
        "password": "secret",
    }
    assert "extra_fields" not in seen[0]


def test_session_execute_chain_exposes_auto_extract_compatibly():
    parameters = inspect.signature(
        mcp_server.hunter_session_execute_chain
    ).parameters

    assert list(parameters)[:3] == ["session_id", "chain_name", "params"]
    assert parameters["auto_extract"].default is True


def test_session_execute_chain_auto_extracts_login_form_and_first_credential(
    tmp_path, monkeypatch
):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []
    login_html = """
    <form action="/cas/login?state=secret-state" method="post">
      <input name="user" type="text">
      <input name="passcode" type="password">
      <input name="execution" type="hidden" value="flow-123">
      <button type="submit" name="_eventId" value="submit">Login</button>
    </form>
    """

    def request_executor(active_session, request):
        seen.append(request)
        url = request["url"]
        method = request["method"]
        if method == "GET" and url.endswith(("/login", "/cas/login")):
            body = login_html
        elif method == "GET" and url.endswith("/admin"):
            body = '<h1>Admin dashboard</h1><a href="/admin/users">Manage</a>'
        else:
            body = "login accepted"
        return {
            "status": "ok",
            "status_code": 200,
            "url": url,
            "headers": {},
            "body": body,
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"target_url": "https://example.test"},
        )
    ))

    assert result["status"] == "ok", (result, seen)
    assert result["data"]["status"] == "complete", (result, seen)
    assert result["data"]["auto_extract"]["status"] == "prepared"
    assert result["data"]["auto_extract"]["candidate_count"] >= 20
    assert result["data"]["auto_extract"]["action"] == (
        "https://example.test/cas/login"
    )
    assert "credentials" not in result["data"]["auto_extract"]
    assert seen[0]["method"] == "GET"
    assert seen[0]["url"] == "https://example.test/login"
    submitted = next(item for item in seen if item["method"] == "POST")
    assert submitted["url"] == (
        "https://example.test/cas/login?state=secret-state"
    )
    assert submitted["data"]["user"] == "admin"
    assert submitted["data"]["passcode"] == "admin"
    assert submitted["data"]["execution"] == "flow-123"
    assert submitted["data"]["_eventId"] == "submit"


def test_auto_extract_does_not_fetch_when_target_url_is_missing(
    tmp_path, monkeypatch
):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []
    monkeypatch.setattr(
        mcp_server,
        "_attack_request_executor",
        lambda active_session, request: seen.append(request) or {},
    )

    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"username": "admin", "password": "secret"},
        )
    ))

    assert result["status"] == "error"
    assert "target_url" in result["error"]
    assert seen == []


def test_auto_extract_no_login_form_falls_back_to_legacy_chain(
    tmp_path, monkeypatch
):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []

    def request_executor(active_session, request):
        seen.append(request)
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": '<form action="/search"><input name="q"></form>',
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={
                "target_url": "https://example.test",
                "username": "operator",
                "password": "secret",
            },
        )
    ))

    assert result["data"]["auto_extract"]["status"] == "no-login-form"
    assert seen[0]["url"] == "https://example.test/login"
    assert seen[1]["url"] == "https://example.test/login"


def test_auto_extract_executes_login_form_without_csrf_field(
    tmp_path, monkeypatch
):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []
    login_html = """
    <form action="/signin" method="post">
      <input name="email" type="email">
      <input name="secret" type="password">
      <button type="submit" name="login" value="1">Login</button>
    </form>
    """

    def request_executor(active_session, request):
        seen.append(request)
        if request["method"] == "GET" and request["url"].endswith("/admin"):
            body = '<h1>Admin dashboard</h1><a href="/admin/users">Manage</a>'
        elif request["method"] == "GET":
            body = login_html
        else:
            body = "login accepted"
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": body,
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"target_url": "https://example.test"},
        )
    ))

    assert result["status"] == "ok", (result, seen)
    submitted = next(item for item in seen if item["method"] == "POST")
    assert submitted["url"] == "https://example.test/signin"
    assert submitted["data"]["email"] == "admin"
    assert submitted["data"]["secret"] == "admin"
    assert submitted["data"]["login"] == "1"
    assert "" not in submitted["data"]


def test_auto_extract_false_preserves_legacy_request_count(
    tmp_path, monkeypatch
):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []

    def request_executor(active_session, request):
        seen.append(request)
        if request["method"] == "GET" and request["url"].endswith("/login"):
            body = '<input name="csrf_token" value="token-123">'
        elif request["method"] == "GET" and request["url"].endswith("/admin"):
            body = '<h1>Admin dashboard</h1><a href="/admin/users">Manage</a>'
        else:
            body = "login accepted"
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": body,
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={
                "target_url": "https://example.test",
                "username": "operator",
                "password": "secret",
            },
            auto_extract=False,
        )
    ))

    assert result["status"] == "ok", (result, seen)
    assert "auto_extract" not in result["data"]
    assert [item["method"] for item in seen] == ["GET", "POST", "GET"]


def test_auto_extract_captcha_form_stops_before_post(tmp_path, monkeypatch):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []
    html = """
    <form action="/login" method="post">
      <input name="username">
      <input name="password" type="password">
      <input name="captcha" placeholder="Captcha">
    </form>
    """

    def request_executor(active_session, request):
        seen.append(request)
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": html,
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"target_url": "https://example.test"},
        )
    ))

    assert result["status"] == "blocked"
    assert result["data"]["auto_extract"]["status"] == "captcha-required"
    assert [item["method"] for item in seen] == ["GET"]


def test_auto_extract_cross_origin_action_stops_before_post(
    tmp_path, monkeypatch
):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_origins": [
                "https://example.test",
                "https://sso.example.test",
            ],
            "allowed_methods": ["GET", "POST"],
        },
    )
    seen = []
    html = """
    <form action="https://sso.example.test/login" method="post">
      <input name="username">
      <input name="password" type="password">
    </form>
    """

    def request_executor(active_session, request):
        seen.append(request)
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": html,
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"target_url": "https://example.test"},
        )
    ))

    assert result["status"] == "blocked"
    assert result["data"]["auto_extract"]["status"] == (
        "cross-origin-action-required"
    )
    assert [item["method"] for item in seen] == ["GET"]


def test_auto_extract_honors_get_login_form_method(tmp_path, monkeypatch):
    store = mcp_server._reset_attack_session_store(tmp_path / "sessions")
    session = store.create(
        "https://example.test",
        authorization={
            "approval_id": "auto-form",
            "approved_by": "operator",
            "allowed_methods": ["GET"],
        },
    )
    seen = []
    html = """
    <form action="/signin" method="get">
      <input name="email" type="email">
      <input name="password" type="password">
    </form>
    """

    def request_executor(active_session, request):
        seen.append(request)
        if request["url"].startswith("https://example.test/admin"):
            body = '<h1>Admin dashboard</h1><a href="/admin/users">Manage</a>'
        else:
            body = html
        return {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": body,
        }

    monkeypatch.setattr(mcp_server, "_attack_request_executor", request_executor)
    result = json.loads(asyncio.run(
        mcp_server.hunter_session_execute_chain(
            session.session_id,
            "login_to_admin",
            params={"target_url": "https://example.test"},
        )
    ))

    assert result["status"] == "ok", (result, seen)
    submitted = seen[2]
    assert submitted["method"] == "GET"
    assert "email=admin" in submitted["url"]
    assert "password=admin" in submitted["url"]
    assert submitted["data"] is None

def test_get_form_credentials_are_not_persisted_in_in_flight_url(tmp_path):
    observed = {}
    chain = AttackChain(
        {
            "name": "get-login-persistence",
            "parameters": {},
            "steps": [
                {
                    "step_id": "submit",
                    "name": "Submit",
                    "action": "request",
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/signin?service=admin#ignored",
                        "data": {"email": "admin", "password": "secret"},
                    },
                }
            ],
        },
        request_executor=lambda session, request: observed.update(
            {
                "request": request,
                "cursor": session.chain_cursors["get-login-persistence"]["in_flight"],
                "persisted": session.state_path.read_text(encoding="utf-8"),
            }
        )
        or {
            "status": "ok",
            "status_code": 200,
            "url": request["url"],
            "headers": {},
            "body": "ok",
        },
    )
    session = AttackSession(
        "https://example.test",
        storage_dir=tmp_path,
        authorization={
            "approval_id": "get-login",
            "approved_by": "operator",
            "allowed_methods": ["GET"],
        },
    )

    result = chain.execute(session)

    assert result["status"] == "complete"
    assert observed["request"]["url"] == (
        "https://example.test/signin?service=admin&email=admin&password=secret#ignored"
    )
    assert observed["request"]["data"] is None
    assert "email=admin" not in observed["persisted"]
    assert "password=secret" not in observed["persisted"]
    assert observed["cursor"]["url"] == "https://example.test/signin"

